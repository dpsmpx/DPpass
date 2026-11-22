//go:build linux

package bridge

import (
    "strings"
    "testing"
    "time"
)

func TestZapret2GoogleStrategyRegistryIsComplete(t *testing.T) {
    names := []string{"plain", "split-1", "split", "tlsrec-split",
        "fake-3", "fake-5", "disorder", "auto"}
    if len(zapret2TestStrategies) != len(names) {
        t.Fatalf("strategy catalog incomplete: %+v", zapret2TestStrategies)
    }
    for _, n := range names {
        tag := zapret2TestStrategies[n]
        if tag == "" { t.Fatalf("missing %s", n) }
        if n == "plain" {
            if tag != zapret2PlainTag { t.Fatal("plain must use its own tag") }
        } else {
            expected := "dppass:test-" + n
            if tag != expected { t.Fatalf("%s: got %q, want %q", n, tag, expected) }
            if _, recognized, err := parseDesyncTag("dppass:exp-" + n); !recognized || err != nil {
                t.Fatalf("invalid underlying experiment tag %s: %v", n, err)
            }
        }
    }
}

func TestZapret2GoogleHTTPResponseClassification(t *testing.T) {
    for _, tc := range []struct {
        http int
        bytes int64
        want string
    }{
        {200, 4096, "ok"}, {204, 0, "empty_body"},
        {301, 0, "redirect"}, {403, 500, "http_status"},
        {500, 0, "http_status"}, {200, 0, "empty_body"},
    } {
        if got := classifyGoogleHTTP(tc.http, tc.bytes, nil); got != tc.want {
            t.Fatalf("http %d bytes %d: %s instead of %s", tc.http, tc.bytes, got, tc.want)
        }
    }
}

func TestZapret2GoogleProbeRejectsArbitraryTagsAndTimeouts(t *testing.T) {
    for _, name := range []string{"https://evil.example", "fake-9", "../split", " plain"} {
        r := ProbeZapret2HTTPS(name, 4*time.Second)
        if r.Outcome != "invalid_strategy" { t.Fatalf("accepted %q", name) }
    }
    r := ProbeZapret2HTTPS("split", 1*time.Millisecond)
    if r.Outcome != "invalid_timeout" { t.Fatalf("accepted invalid timeout: %+v", r) }
}

func TestZapret2GoogleProbeWireContainsNoPayloadOrDestination(t *testing.T) {
    r := Zapret2HTTPSResult{Outcome:"http_status", HTTPStatus:403,
        BodyBytes:15, Elapsed:1500*time.Millisecond,
        AppliedDelta:2, SkippedDelta:1}
    got := string(r.Wire())
    if got != "v1\thttp_status\t403\t15\t1500\t2\t1" {
        t.Fatalf("unexpected probe wire: %q", got)
    }
    if strings.Contains(got, "google.com") || strings.Contains(got, "http://") {
        t.Fatal("serialized response revealed URL")
    }
}
