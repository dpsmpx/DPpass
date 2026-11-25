// Package localdpi owns the stable method identifiers used by local AUTO.
// It has no socket, platform, or third-party dependencies.
package localdpi

import "sort"

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
    trainTCP bool
    trainQUIC bool
    profileOrder int // explicit planner profile; -1 means AUTO-only
}

// Entries declare the current socket candidates and learning eligibility.
// A layout change requires a new model format, never migration of old weights.
// Packet-level ROOT capabilities are separate.
var methods = [...]method{
    {"split-1", tlsMask | httpMask, true, false, 4},
    {"split", tlsMask | httpMask, true, false, 3},
    {"fake-3", tlsMask | httpMask | quicMask, true, true, 0},
    {"fake-5", tlsMask | httpMask | quicMask, true, true, 1},
    {"disorder", tlsMask | httpMask, true, false, 2},
    {"tlsrec-split", tlsMask, true, false, 5},
    {"pass", tlsMask | httpMask | quicMask, false, true, -1},
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

// Model output positions follow the current catalog: TCP first, then QUIC.
// HTTP uses the TCP output when the method supports HTTP.
func TCPOutputCount() int {
    count := 0
    for _, m := range methods { if m.trainTCP { count++ } }
    return count
}

func ModelOutputCount() int {
    count := TCPOutputCount()
    for _, m := range methods { if m.trainQUIC { count++ } }
    return count
}

func NeuralIndex(id string, t Transport) int {
    if mask(t) == 0 { return -1 }
    index := 0
    if t == QUIC { index = TCPOutputCount() }
    for _, m := range methods {
        train := m.trainTCP
        if t == QUIC { train = m.trainQUIC }
        if !train { continue }
        if m.id == id && m.transports & mask(t) != 0 { return index }
        index++
    }
    return -1
}

// Profiles returns explicitly selectable planner profiles.
func Profiles() []string {
    selected := make([]method, 0, len(methods))
    for _, m := range methods {
        if m.profileOrder >= 0 { selected = append(selected, m) }
    }
    sort.Slice(selected, func(i,j int) bool { return selected[i].profileOrder < selected[j].profileOrder })
    out := make([]string, 0, len(selected))
    for _, m := range selected { out = append(out, m.id) }
    return out
}

// HTMLIndex identifies a trainable TLS method for content calibration.
func HTMLIndex(id string) int {
    return NeuralIndex(id,TLS)
}
