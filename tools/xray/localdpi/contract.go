package localdpi

import "fmt"

// ContractVersion changes only for incompatible executor/evidence semantics.
const ContractVersion = 1

type ExecutorKind uint8

const (
    VPNSocket ExecutorKind = iota + 1
    RootSocket
    RootPacket
)

func (k ExecutorKind) valid(rootAuthorized bool) bool {
    switch k {
    case VPNSocket:
        return true
    case RootSocket, RootPacket:
        return rootAuthorized
    default:
        return false
    }
}

// Support is an explicit assertion by a runtime executor, not inferred
// from the existence of a method in the catalog. Root consent must be
// checked by the caller; the contract cannot acquire privileges.
type Support struct {
    Transport Transport
    MethodID string
}

type Capabilities struct {
    kind ExecutorKind
    supported map[Support]struct{}
}

// NewCapabilities fails closed for unknown methods, incompatible transport,
// duplicates and unauthorized root. The input slice is not retained.
func NewCapabilities(kind ExecutorKind, rootAuthorized bool, entries []Support) (Capabilities, error) {
    if !kind.valid(rootAuthorized) {
        return Capabilities{}, fmt.Errorf("executor unavailable or unauthorized")
    }
    out := Capabilities{kind: kind, supported: make(map[Support]struct{}, len(entries))}
    for _, entry := range entries {
        known := false
        for _, id := range Candidates(entry.Transport) {
            if id == entry.MethodID { known = true; break }
        }
        if !known { return Capabilities{}, fmt.Errorf("unsupported method/transport") }
        if _, duplicate := out.supported[entry]; duplicate {
            return Capabilities{}, fmt.Errorf("duplicate method/transport")
        }
        out.supported[entry] = struct{}{}
    }
    return out,nil
}

func (c Capabilities) Kind() ExecutorKind { return c.kind }

func (c Capabilities) Allows(t Transport, id string) bool {
    _, ok := c.supported[Support{Transport:t, MethodID:id}]
    return ok
}

// Candidates preserves catalog order, rather than executor registration order.
func (c Capabilities) Candidates(t Transport) []string {
    out := []string{}
    for _, id := range Candidates(t) {
        if c.Allows(t,id) { out = append(out,id) }
    }
    return out
}

// FlowIdentity belongs to the local engine only. It contains no addresses,
// domain names, account data or application payload. An executor change or
// network generation change invalidates old results.
type FlowIdentity struct {
    Executor ExecutorKind
    Generation uint64
    Transport Transport
    MethodID string
}

func (f FlowIdentity) Matches(c Capabilities, generation uint64) bool {
    return f.Executor == c.Kind() && f.Generation == generation &&
        c.Allows(f.Transport,f.MethodID)
}

type EvidenceKind uint8

const (
    Unknown EvidenceKind = iota
    Downstream
    FirstReplyTimeout
    Cancelled
    RouteUnavailable
    VerifiedContent
)

// Evidence records only a classification and byte count. VerifiedContent
// must be supplied by an independent application-level verifier, never by
// a generic socket read or a successful handshake.
type Evidence struct {
    Kind EvidenceKind
    Bytes int64
}

func SocketClose(received int64) Evidence {
    if received > 0 { return Evidence{Kind:Downstream, Bytes:received} }
    if received == 0 { return Evidence{Kind:Cancelled} }
    return Evidence{Kind:Unknown}
}

// A timeout is first-reply evidence only when the initial request was
// sent, nothing has replied, and no downstream data has been observed.
// Callers must separately confirm an actual timeout, not a normal close.
func SocketFirstReplyTimeout(sent, replied bool, received int64) Evidence {
    if sent && !replied && received == 0 { return Evidence{Kind:FirstReplyTimeout} }
    return Evidence{Kind:Unknown}
}
