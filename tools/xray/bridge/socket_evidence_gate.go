//go:build linux

package bridge

import (
    "sync"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

// socketEvidenceGate serializes one flow's learning and reachability updates.
// The selector still independently checks the active network and cache entry.
type socketEvidenceGate struct {
    mu sync.Mutex
    finished bool
}

// A valid observation is terminal even if the selector rejects a stale flow.
// A neutral close seals the allowance without publishing a label.
func (g *socketEvidenceGate) submit(pick *adaptivePick, evidence localdpi.Evidence, close bool,
    deliver func(*adaptivePick,localdpi.Evidence)) bool {
    g.mu.Lock()
    defer g.mu.Unlock()
    if g.finished {return false}
    valid:=socketEvidenceAdmissible(pick,evidence)
    if valid || close {g.finished=true}
    if !valid {return false}
    deliver(pick,evidence)
    return true
}

// First-reply reachability is not a learning label. Do not let a late
// reply reverse the timeout policy after this flow's allowance was consumed.
func (g *socketEvidenceGate) retain(pick *adaptivePick, deliver func(*adaptivePick)) bool {
    g.mu.Lock()
    defer g.mu.Unlock()
    if g.finished || !socketPickAdmissible(pick) || pick.flow.MethodID!="pass" {return false}
    deliver(pick)
    return true
}

func (g *socketEvidenceGate) seal() {
    g.mu.Lock()
    defer g.mu.Unlock()
    g.finished=true
}
