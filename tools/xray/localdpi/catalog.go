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
    {"split-1", tlsMask, true, false, 4},
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

// SupportsMethod reports the catalog's protocol admission, not runtime
// availability. It does not allocate or imply executor registration.
func SupportsMethod(t Transport,id string) bool {
    allowed:=mask(t)
    if allowed==0 {return false}
    for _,m:=range methods {
        if m.id==id {return m.transports & allowed != 0}
    }
    return false
}

// Candidates returns an independent slice in the existing selection order.
func Candidates(t Transport) []string {
    out := make([]string, 0, len(methods))
    for _, m := range methods {
        if m.transports & mask(t) != 0 { out = append(out, m.id) }
    }
    return out
}

// The learning group is independent of the transport admission mask.
// HTTP shares the TCP output positions, including gaps for TLS-only methods.
func (m method) trainable(t Transport) bool {
    return (t == TLS && m.trainTCP) || (t == QUIC && m.trainQUIC)
}

// Model output positions follow the current catalog: TCP first, then QUIC.
func ModelMethods(t Transport) []string {
    out := []string{}
    for _, m := range methods {
        if m.trainable(t) {
            out = append(out, m.id)
        }
    }
    return out
}

func modelGroupCount(t Transport) int {
    n := 0
    for _, m := range methods {
        if m.trainable(t) { n++ }
    }
    return n
}

func TCPOutputCount() int { return modelGroupCount(TLS) }

func ModelOutputCount() int { return TCPOutputCount() + modelGroupCount(QUIC) }

// Include the ordered method IDs, not merely the number of outputs.
// Bump the schema prefix for changes to feature or training semantics.
func ModelFormat() string {
    return "dppass-strategy-mlp-v5:tcp=" + strings.Join(ModelMethods(TLS), ",") +
        ";quic=" + strings.Join(ModelMethods(QUIC), ",")
}

// NeuralIndex runs on the per-connection selection path. Walk the catalog
// directly rather than allocating a model-method slice for every lookup.
func NeuralIndex(id string, t Transport) int {
    allowed := mask(t)
    if allowed == 0 { return -1 }
    group, index := TLS, 0
    if t == QUIC { group, index = QUIC, TCPOutputCount() }
    for _, m := range methods {
        if !m.trainable(group) { continue }
        if m.id == id {
            if m.transports & allowed != 0 { return index }
            return -1
        }
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
