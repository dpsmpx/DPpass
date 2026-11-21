//go:build linux

package zapret2

// Plan is the single cross-platform strategy decision. Android retains only
// packet/socket IO, while Alpine can run this exact planner as a separate
// process. It never requires elevated OS privileges.
type Plan struct {
    Strategy string `json:"strategy"`
    Network string `json:"network"`
    Applied bool `json:"applied"`
    Cut int `json:"cut,omitempty"`
    Fake []byte `json:"fake,omitempty"`
    TTL int `json:"ttl,omitempty"`
    Repeats int `json:"repeats,omitempty"`
    Reason string `json:"reason,omitempty"`
}

func BuildPlan(tag, network string, first []byte) (Plan, error) {
    mode, ok, err := ParseTag(tag)
    if err != nil { return Plan{}, err }
    if !ok { return Plan{}, nil }
    p := Plan{Strategy: tag, Network: network, TTL: mode.TTL}
    switch network {
    case "tcp":
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
