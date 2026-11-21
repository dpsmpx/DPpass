//go:build linux

package zapret2

import (
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
    case "disorder": return Mode{Kind: Disorder, TTL: 1}, true, nil
    case "split": return Mode{Kind: Split}, true, nil
    case "split-1": return Mode{Kind: SplitFirst}, true, nil
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
    return []string{"fake-3", "fake-5", "disorder", "split", "split-1"}
}
