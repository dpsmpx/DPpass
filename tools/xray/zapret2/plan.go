//go:build linux

package zapret2

import "fmt"

// Plan is the single cross-platform strategy decision. Android retains only
// packet/socket IO, while Alpine can run this exact planner as a separate
// process. It never requires elevated OS privileges.
type Plan struct {
    Strategy string `json:"strategy"`
    Network string `json:"network"`
    Applied bool `json:"applied"`
    Cut int `json:"cut,omitempty"`
    Fake []byte `json:"fake,omitempty"`
    // Rewrite is an optional intact-handshake TLS record encoding. Only the
    // explicit TLS-record+TCP strategy may return one; input bytes stay intact.
    Rewrite []byte `json:"rewrite,omitempty"`
    TTL int `json:"ttl,omitempty"`
    Repeats int `json:"repeats,omitempty"`
    Reason string `json:"reason,omitempty"`
}

func BuildPlan(tag, network string, first []byte) (Plan, error) {
    return buildPlan(tag,network,first,false)
}

func buildPlan(tag, network string, first []byte, diagnostic bool) (Plan,error) {
    mode, ok, err := ParseTag(tag)
    if err != nil { return Plan{}, err }
    if !ok { return Plan{}, nil }
    if mode.Kind == Auto { return Plan{}, fmt.Errorf("adaptive mode must be resolved per connection before Alpine planning") }
    p := Plan{Strategy: tag, Network: network, TTL: mode.TTL}
    if mode.Kind == Pass { p.Reason = "intentional unmodified transport baseline"; return p, nil }
    switch network {
    case "tcp":
        if mode.Kind == TLSRecordSplit {
            if payload, cut, ok := splitTLSRecordClientHello(first,diagnostic); ok {
                p.Applied = true
                p.Rewrite = payload
                p.Cut = cut
            } else {
                p.Reason = "complete single-record TLS ClientHello required"
            }
            return p, nil
        }
        if mode.Kind == SplitSecond {
            if !IsTLSClientHelloPrefix(first) || len(first) <= 2 { p.Reason = "TLS ClientHello prefix required"; return p, nil }
            p.Applied = true
            p.Cut = 2
            return p, nil
        }
        if mode.Kind == SplitFirst {
            if !IsTLSClientHelloPrefix(first) { p.Reason = "not TLS ClientHello"; return p, nil }
            p.Applied = true
            p.Cut = 1
            return p, nil
        }
        s, e, found := FirstHostRange(first)
        if found {
            p.Applied = true
            p.Cut = s + (e-s)/2
            if mode.Kind == Fake { p.Fake = FakeChunk(first[:p.Cut], s, e) }
            return p, nil
        }
        if IsTLSClientHelloPrefix(first) {
            p.Applied = true
            p.Cut = 1
            p.Reason = "SNI-less TLS fallback"
            return p, nil
        }
        p.Reason = "no supported TLS or HTTP hostname"
    case "udp":
        if mode.Kind != Fake || !IsQUICInitial(first) {
            p.Reason = "not a fake-enabled QUIC Initial"
            return p, nil
        }
        p.Applied = true
        p.Fake = FakeQUICInitial(first)
        p.Repeats = 6
    default:
        p.Reason = "unsupported transport"
    }
    return p, nil
}
