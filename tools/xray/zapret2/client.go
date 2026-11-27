//go:build linux

package zapret2

import (
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

// SetPlannerSocket selects Alpine for planning, except the explicitly tagged
// native experiment. Empty path retains the in-process shared planner.
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
    return planFor(tag,network,first,false)
}

// PlanForDiagnostic uses the same strategy and validation. Only local
// native encoder accounting differs; the external planner wire is unchanged.
func PlanForDiagnostic(tag, network string, first []byte) (Plan,error) {
    return planFor(tag,network,first,true)
}

func planFor(tag,network string,first []byte,diagnostic bool) (Plan,error) {
    if _,err:=validateRequest(tag,network,first);err!=nil {return Plan{},err}
    // The explicitly tagged test build owns this one encoder in-process.
    // This is a predetermined dispatch rule, not a fallback after an IPC
    // failure. All other selected Alpine methods still fail closed.
    path := PlannerSocket()
    if localNativePlan(tag,network) || path=="" {
        p,err:=buildPlan(tag,network,first,diagnostic)
        if err!=nil {return Plan{},err}
        if err:=validatePlan(tag,network,first,p);err!=nil {return Plan{},err}
        return p,nil
    }
    conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
    if err != nil { return Plan{}, fmt.Errorf("Alpine strategy daemon unavailable: %w", err) }
    defer conn.Close()
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
    return p, nil
}
