// Package localdpi owns the stable method identifiers used by local AUTO.
// It has no socket, platform, or third-party dependencies.
package localdpi

import "sort"

// LegacyModelABI is the fixed output layout accepted by v2/v3 models.
// New trainable methods must use an explicit migration, not reuse a slot.
const (
    LegacyModelABI = 1
    LegacyTCPOutputs = 6
    LegacyQUICOutputs = 3
    LegacyModelOutputs = LegacyTCPOutputs + LegacyQUICOutputs
)

type Transport uint8

const (
    TLS Transport = iota + 1
    HTTP
    QUIC
)

type transportMask uint8

const (
    tlsMask transportMask = 1 << iota
    httpMask
    quicMask
)

type method struct {
    id string
    transports transportMask
    tcpIndex int // legacy neural output, -1 means no output
    quicIndex int
    profileOrder int // legacy explicit planner profile; -1 means AUTO-only
}

// Append new methods only through a versioned model migration. Existing
// order and neural indices are part of the on-device model ABI.
// Entries describe implemented DPpass socket candidates, not claims of
// upstream equivalence or packet-level ROOT support.
var methods = [...]method{
    {"split-1", tlsMask | httpMask, 0, -1, 4},
    {"split", tlsMask | httpMask, 1, -1, 3},
    {"fake-3", tlsMask | httpMask | quicMask, 2, 6, 0},
    {"fake-5", tlsMask | httpMask | quicMask, 3, 7, 1},
    {"disorder", tlsMask | httpMask, 4, -1, 2},
    {"tlsrec-split", tlsMask, 5, -1, 5},
    {"pass", tlsMask | httpMask | quicMask, -1, 8, -1},
}

func mask(t Transport) transportMask {
    switch t {
    case TLS: return tlsMask
    case HTTP: return httpMask
    case QUIC: return quicMask
    default: return 0
    }
}

// Candidates returns an independent slice in the existing selection order.
func Candidates(t Transport) []string {
    out := make([]string, 0, len(methods))
    for _, m := range methods {
        if m.transports & mask(t) != 0 { out = append(out, m.id) }
    }
    return out
}

// NeuralIndex preserves the 6 TCP + 3 QUIC output layout of existing models.
func NeuralIndex(id string, t Transport) int {
    for _, m := range methods {
        if m.id != id || m.transports & mask(t) == 0 { continue }
        if t == QUIC { return m.quicIndex }
        return m.tcpIndex
    }
    return -1
}

// LegacyProfiles preserves the explicit planner profile order.
func LegacyProfiles() []string {
    selected := make([]method, 0, len(methods))
    for _, m := range methods {
        if m.profileOrder >= 0 { selected = append(selected, m) }
    }
    sort.Slice(selected, func(i,j int) bool { return selected[i].profileOrder < selected[j].profileOrder })
    out := make([]string, 0, len(selected))
    for _, m := range selected { out = append(out, m.id) }
    return out
}

// LegacyHTMLIndex admits only the original HTTPS calibration outputs.
// A diagnostic-only profile or baseline has no calibration slot.
func LegacyHTMLIndex(id string) int {
    idx:=NeuralIndex(id,TLS)
    if idx<0 || idx>=LegacyTCPOutputs {return -1}
    return idx
}
