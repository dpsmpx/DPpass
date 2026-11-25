// Package localdpi owns the stable method identifiers used by local AUTO.
// It has no socket, platform, or third-party dependencies.
package localdpi

import (
    "sort"
    "strings"
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
    trainTCP bool
    trainQUIC bool
    profileOrder int // explicit planner profile; -1 means AUTO-only
}

// Entries declare the current socket candidates and learning eligibility.
// A changed learning layout invalidates old models through ModelFormat.
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
// HTTP uses a TCP output only if the method also supports HTTP.
func ModelMethods(t Transport) []string {
    out := []string{}
    for _, m := range methods {
        if (t == TLS && m.trainTCP) || (t == QUIC && m.trainQUIC) {
            out = append(out, m.id)
        }
    }
    return out
}

func TCPOutputCount() int { return len(ModelMethods(TLS)) }

func ModelOutputCount() int { return TCPOutputCount() + len(ModelMethods(QUIC)) }

// Include the ordered method IDs, not merely the number of outputs.
// Bump the schema prefix for changes to feature or training semantics.
func ModelFormat() string {
    return "dppass-strategy-mlp-v4:tcp=" + strings.Join(ModelMethods(TLS), ",") +
        ";quic=" + strings.Join(ModelMethods(QUIC), ",")
}

func NeuralIndex(id string, t Transport) int {
    if mask(t) == 0 { return -1 }
    group, offset := TLS, 0
    if t == QUIC { group, offset = QUIC, TCPOutputCount() }
    for index, candidate := range ModelMethods(group) {
        if candidate != id { continue }
        for _, m := range methods {
            if m.id == id && m.transports & mask(t) != 0 { return offset + index }
        }
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
