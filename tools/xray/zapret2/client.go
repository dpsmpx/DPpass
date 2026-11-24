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
    if path != "" && (!strings.HasPrefix(path, "/") || len(path) > 99 || strings.Contains(path, "\x00")) {
        return errors.New("invalid Alpine planner Unix socket")
    }
    socketPath.Store(path)
    return nil
}

func PlannerSocket() string { return socketPath.Load().(string) }

// PlanFor never falls back to a different algorithm when the Alpine
// process has been selected but is down: a silent bypass would be unsafe.
func PlanFor(tag, network string, first []byte) (Plan, error) {
    if len(first) > MaxFirst { return Plan{}, errors.New("first packet too large") }
    // The explicitly tagged test build owns this one encoder in-process.
    // This is a predetermined dispatch rule, not a fallback after an IPC
    // failure. All other selected Alpine methods still fail closed.
    path := PlannerSocket()
    if localNativePlan(tag,network) || path=="" {
        p,err:=BuildPlan(tag,network,first)
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
