package localdpi

import "fmt"

// ExecutorSet is an immutable snapshot of admitted executor capabilities.
// It describes only what the caller has actually registered, not what an OS
// might theoretically support. It neither starts a process nor acquires root.
type ExecutorSet struct {
    byKind map[ExecutorKind]Capabilities
}

// NewExecutorSet rejects empty/unknown or duplicate executor declarations.
// Root capabilities must have been constructed after the caller's permission
// checks. This does not replace a runtime OS capability probe.
func NewExecutorSet(entries ...Capabilities) (ExecutorSet,error) {
    if len(entries)==0 {
        return ExecutorSet{},fmt.Errorf("no registered executors")
    }
    s:=ExecutorSet{byKind:make(map[ExecutorKind]Capabilities,len(entries))}
    for _,c:=range entries {
        if !c.kind.valid(true) || c.supported==nil {
            return ExecutorSet{},fmt.Errorf("invalid executor capabilities")
        }
        if _,exists:=s.byKind[c.kind];exists {
            return ExecutorSet{},fmt.Errorf("duplicate executor")
        }
        // Own the registration map even if another package-local caller
        // retains the original capability value.
        owned:=Capabilities{kind:c.kind,supported:make(map[Support]struct{},len(c.supported))}
        for entry:=range c.supported {
            if !SupportsMethod(entry.Transport,entry.MethodID) {
                return ExecutorSet{},fmt.Errorf("invalid registered method/transport")
            }
            owned.supported[entry]=struct{}{}
        }
        s.byKind[c.kind]=owned
    }
    return s,nil
}

// Candidates never silently substitutes another executor, particularly
// ROOT for VPN. Empty means no registered method for the requested context.
func (s ExecutorSet) Candidates(kind ExecutorKind,t Transport) []string {
    return s.byKind[kind].Candidates(t)
}

// Admit verifies method, transport, executor and network generation.
// The caller must supply the active executor and current generation under
// its own session lock. An old flow cannot train a different executor.
func (s ExecutorSet) Admit(flow FlowIdentity,active ExecutorKind,generation uint64) bool {
    if flow.Executor!=active {return false}
    caps,ok:=s.byKind[active]
    return ok && flow.Matches(caps,generation)
}
