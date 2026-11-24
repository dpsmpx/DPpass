//go:build linux

package zapret2

import (
    "bufio"
    "encoding/json"
    "errors"
    "fmt"
    "io"
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

// SetPlannerSocket selects Alpine as the only decision maker. Empty path
// retains the same in-process shared planner on platforms without Alpine.
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
    if localNativePlan(tag,network) { return BuildPlan(tag,network,first) }
    path := PlannerSocket()
    if path == "" { return BuildPlan(tag, network, first) }
    conn, err := net.DialTimeout("unix", path, 300*time.Millisecond)
    if err != nil { return Plan{}, fmt.Errorf("Alpine strategy daemon unavailable: %w", err) }
    defer conn.Close()
    if err = conn.SetDeadline(time.Now().Add(2*time.Second)); err != nil { return Plan{}, err }
    if err = json.NewEncoder(conn).Encode(Request{Tag:tag, Network:network, First:first}); err != nil {
        return Plan{}, fmt.Errorf("send Alpine strategy: %w", err)
    }
    // Reject unknown protocol output and oversized responses instead of
    // accepting a truncated, malformed or foreign planner reply.
    dec := json.NewDecoder(io.LimitReader(bufio.NewReader(conn), 96*1024))
    dec.DisallowUnknownFields()
    var reply Response
    if err = dec.Decode(&reply); err != nil { return Plan{}, fmt.Errorf("Alpine strategy reply: %w", err) }
    if reply.Error != "" { return Plan{}, errors.New(reply.Error) }
    p := reply.Plan
    if p.Network != network || p.Strategy != tag || (p.Applied && (network == "tcp" && (p.Cut < 1 || p.Cut >= len(first)))) {
        return Plan{}, errors.New("invalid Alpine strategy decision")
    }
    if network == "tcp" {
        if tag == TagPrefix+"tlsrec-split" && p.Applied &&
            (len(p.Rewrite) != len(first)+5 || p.Cut < 9 || p.Cut >= len(p.Rewrite)-5) {
            return Plan{}, errors.New("invalid Alpine TLS record rewrite")
        }
        if tag != TagPrefix+"tlsrec-split" && len(p.Rewrite) != 0 {
            return Plan{}, errors.New("unexpected Alpine TLS rewrite")
        }
    }
    if network == "udp" && p.Applied && (p.Repeats < 1 || p.Repeats > 16 || len(p.Fake) != len(first)) {
        return Plan{}, errors.New("invalid Alpine QUIC plan")
    }
    return p, nil
}
