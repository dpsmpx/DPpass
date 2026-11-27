//go:build linux

package zapret2

import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "fmt"
    "strconv"
    "strings"
)

// Strategy represents a userspace DPI strategy. The same code is imported by
// Xray's protected-socket transport adapter and the Alpine strategy process.
type Kind string
const (
    Fake Kind = "fake"
    Disorder Kind = "disorder"
    Split Kind = "split"
    SplitFirst Kind = "split-1"
    SplitSecond Kind = "split-2"
    MultiSplit Kind = "multisplit" // explicit DPTS TCP probe
    Auto Kind = "auto"
    TLSRecordSplit Kind = "tlsrec-split"
    HTTPHostCase Kind = "http-hostcase" // explicit diagnostic only
    HTTPHostOWS Kind = "http-hostows" // fixed loopback diagnostic only
    Pass Kind = "pass" // intentional untouched QUIC baseline, AUTO only
)
type Mode struct {
    Kind Kind `json:"kind"`
    TTL int `json:"ttl"`
}
const TagPrefix = "dppass:exp-"
const MinFakeTTL = 1
const MaxFakeTTL = 64

// ParseTag is the sole authority for strategy names and TTL limits.
func ParseTag(tag string) (Mode, bool, error) {
    v, ok := strings.CutPrefix(tag, TagPrefix)
    if !ok { return Mode{}, false, nil }
    switch v {
    case "auto": return Mode{Kind: Auto}, true, nil
    case "disorder": return Mode{Kind: Disorder, TTL: 1}, true, nil
    case "split": return Mode{Kind: Split}, true, nil
    case "split-1": return Mode{Kind: SplitFirst}, true, nil
    case "split-2": return Mode{Kind: SplitSecond}, true, nil
    case "multisplit": return Mode{Kind: MultiSplit}, true, nil
    case "tlsrec-split": return Mode{Kind: TLSRecordSplit}, true, nil
    case "pass": return Mode{Kind: Pass}, true, nil
    case "http-hostcase": return Mode{Kind: HTTPHostCase}, true, nil
    case "http-hostows": return Mode{Kind: HTTPHostOWS}, true, nil
    }
    if ttlStr, yes := strings.CutPrefix(v, "fake-"); yes {
        ttl, err := strconv.Atoi(ttlStr)
        if err != nil || ttl < MinFakeTTL || ttl > MaxFakeTTL {
            return Mode{}, true, fmt.Errorf("TTL %q must be %d..%d", ttlStr, MinFakeTTL, MaxFakeTTL)
        }
        return Mode{Kind: Fake, TTL: ttl}, true, nil
    }
    return Mode{}, true, fmt.Errorf("unknown desync mode %q", v)
}

func Profiles() []string {
    return localdpi.Profiles()
}
