//go:build linux

package bridge

import (
    "context"
    "sync"
)

// The request context carries no destination, payload or account data.
// Each private diagnostic socket may record only against its own request.
type diagnosticRequestKey struct{}

type diagnosticRequestCounters struct {
    mu sync.Mutex
    applied int64
    skipped int64
    finished bool
}

func newDiagnosticRequestContext(parent context.Context) (context.Context,*diagnosticRequestCounters) {
    counters:=&diagnosticRequestCounters{}
    return context.WithValue(parent,diagnosticRequestKey{},counters),counters
}

func diagnosticRequestFromContext(ctx context.Context) *diagnosticRequestCounters {
    counters,_:=ctx.Value(diagnosticRequestKey{}).(*diagnosticRequestCounters)
    return counters
}

// A missing context never falls back to the aggregate diagnostic counters.
// Late writes may update process telemetry but cannot revise a returned report.
func (c *diagnosticRequestCounters) record(applied bool) {
    if c==nil {return}
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.finished {return}
    if applied {c.applied++} else {c.skipped++}
}

func (c *diagnosticRequestCounters) finish() (int64,int64) {
    if c==nil {return 0,0}
    c.mu.Lock()
    defer c.mu.Unlock()
    c.finished=true
    return c.applied,c.skipped
}
