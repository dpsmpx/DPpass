//go:build linux

package zapret2

import (
    "context"
    "encoding/json"
    "errors"
    "fmt"
    "net"
    "strings"
    "sync/atomic"
    "time"
)

// Request/Response are shared by the Android transport adapter and the
// process inside Alpine; they are the only IPC wire protocol definition.
type Request struct {
    Tag string `json:"tag"`
    Network string `json:"network"`
    First []byte `json:"first"`
}
type Response struct {
    Plan Plan `json:"plan"`
    Error string `json:"error,omitempty"`
}

const MaxFirst = 32 * 1024

var socketPath atomic.Value

func init() { socketPath.Store("") }

// SetPlannerSocket selects Alpine for planning, except explicitly tagged
// native experiments. Empty path retains the in-process shared planner.
func SetPlannerSocket(path string) error {
    if path != "" && !ValidPlannerSocketPath(path) {
        return errors.New("invalid Alpine planner Unix socket")
    }
    socketPath.Store(path)
    return nil
}

// ValidPlannerSocketPath is shared by daemon and client. Go string length
// is the byte length, matching the Unix sockaddr path and Android UTF-8.
func ValidPlannerSocketPath(path string) bool {
    return strings.HasPrefix(path,"/") && len(path)<=99 && !strings.Contains(path,"\x00")
}

func PlannerSocket() string { return socketPath.Load().(string) }

// PlanFor never falls back to a different algorithm when the Alpine
// process has been selected but is down: a silent bypass would be unsafe.
func PlanFor(tag, network string, first []byte) (Plan, error) {
    return PlanForContext(context.Background(),tag,network,first,false)
}

// PlanForDiagnostic uses the same strategy and validation. Only local
// native encoder accounting differs; the external planner wire is unchanged.
func PlanForDiagnostic(tag, network string, first []byte) (Plan,error) {
    return PlanForContext(context.Background(),tag,network,first,true)
}

// PlanForLocalTLSFixture is reserved for the fixed loopback self-test.
// A native build must prove that the C encoder succeeded, not that its
// ordinary portable fallback happened to produce the same bytes.
func PlanForLocalTLSFixture(first []byte) (Plan,error) {
    return PlanForLocalTLSFixtureContext(context.Background(),first)
}

func PlanForLocalTLSFixtureContext(ctx context.Context,first []byte) (Plan,error) {
    if err:=ctx.Err();err!=nil {return Plan{},err}
    tag:=TagPrefix+"tlsrec-split"
    if _,err:=validateRequest(tag,"tcp",first);err!=nil {return Plan{},err}
    // The fixture is a single complete ClientHello with the fixed SNI.
    recordLen,_,ok:=tlsRecordSplitPosition(first)
    if !ok || len(first)!=5+recordLen {return Plan{},errors.New("invalid local TLS fixture record")}
    s,end,ok:=SNIRange(first)
    if !ok || string(first[s:end])!="example.com" {return Plan{},errors.New("invalid local TLS fixture name")}
    if !localNativePlan(tag,"tcp") {return PlanForContext(ctx,tag,"tcp",first,true)}
    p,err:=strictNativeLocalTLSPlan(first)
    if err!=nil {return Plan{},err}
    if err:=validatePlan(tag,"tcp",first,p);err!=nil {return Plan{},err}
    return p,nil
}

// PlanForLocalTLSChainContext is only called by the fixed loopback
// adapter. Unlike ordinary PlanForContext it requires the native encoder
// on tagged builds and has no portable fallback there.
func PlanForLocalTLSChainContext(ctx context.Context,first []byte) (Plan,error) {
    if err:=ctx.Err();err!=nil {return Plan{},err}
    tag:=TagPrefix+"tlsrec-chain"
    if _,err:=validateRequest(tag,"tcp",first);err!=nil {return Plan{},err}
    if _,_,ok:=localTLSRecordChainPositions(first);!ok {return Plan{},errors.New("invalid local TLS chain fixture")}
    if !nativeLocalTLSChainEnabled() {return PlanForContext(ctx,tag,"tcp",first,true)}
    p,err:=strictNativeLocalTLSChainPlan(first)
    if err!=nil {return Plan{},err}
    if err:=validatePlan(tag,"tcp",first,p);err!=nil {return Plan{},err}
    if err:=ctx.Err();err!=nil {return Plan{},err}
    return p,nil
}

// PlanForContext cancels only the caller's planner request, not the daemon.
func PlanForContext(ctx context.Context,tag,network string,first []byte,diagnostic bool) (Plan,error) {
    if err:=ctx.Err();err!=nil {return Plan{},err}
    if _,err:=validateRequest(tag,network,first);err!=nil {return Plan{},err}
    // Explicitly tagged native experiments have predetermined dispatch.
    // The HTTP exception is restricted to the fixed local diagnostic;
    // normal HTTP and all other selected Alpine methods fail closed.
    path := PlannerSocket()
    if localNativePlan(tag,network) || localNativeHTTPDiagnostic(tag,network,first,diagnostic) || path=="" {
        p,err:=buildPlan(tag,network,first,diagnostic)
        if err!=nil {return Plan{},err}
        if err:=validatePlan(tag,network,first,p);err!=nil {return Plan{},err}
        return p,nil
    }
    dialer:=net.Dialer{Timeout:300*time.Millisecond}
    conn, err := dialer.DialContext(ctx,"unix",path)
    if err != nil { return Plan{}, fmt.Errorf("Alpine strategy daemon unavailable: %w", err) }
    defer conn.Close()
    stopCancel:=context.AfterFunc(ctx,func(){_ = conn.Close()})
    defer stopCancel()
    if err = conn.SetDeadline(time.Now().Add(2*time.Second)); err != nil { return Plan{}, err }
    if err = json.NewEncoder(conn).Encode(Request{Tag:tag, Network:network, First:first}); err != nil {
        return Plan{}, fmt.Errorf("send Alpine strategy: %w", err)
    }
    // Reject unknown protocol output and oversized responses instead of
    // accepting a truncated, malformed or foreign planner reply.
    reply,err:=readResponse(conn)
    if err!=nil {return Plan{},fmt.Errorf("Alpine strategy reply: %w",err)}
    if reply.Error != "" { return Plan{}, errors.New(reply.Error) }
    p := reply.Plan
    if err := validatePlan(tag,network,first,p); err != nil { return Plan{},err }
    if err:=ctx.Err();err!=nil {return Plan{},err}
    return p, nil
}
