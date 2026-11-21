//go:build linux

package zapret2

import (
    "bytes"
    "encoding/json"
    "net"
    "path/filepath"
    "testing"
    "time"
)

func TestOnePlannerForTCPSplitAndFake(t *testing.T) {
    // Realistic complete HTTP Host (TLS SNI and ECH cases are covered by
    // bridge/desync_test.go with crypto/tls ClientHello).
    http := []byte("GET / HTTP/1.1\r\nHost: video.example.org\r\n\r\n")
    s, e, ok := FirstHostRange(http)
    if !ok { t.Fatal("Host header was not detected") }
    for _, mode := range []string{"fake-3", "fake-5", "disorder", "split"} {
        p, err := BuildPlan(TagPrefix+mode, "tcp", http)
        if err != nil || !p.Applied || p.Cut != s+(e-s)/2 {
            t.Fatalf("%s: plan %+v: %v", mode, p, err)
        }
        if mode == "fake-3" || mode == "fake-5" {
            if len(p.Fake) != p.Cut || bytes.Equal(p.Fake, http[:p.Cut]) {
                t.Fatalf("%s: fake not applied", mode)
            }
        } else if len(p.Fake) != 0 {
            t.Fatalf("%s: unexpected decoy bytes", mode)
        }
    }
    tls := []byte{22, 3, 3, 0, 4, 1, 0, 0, 0}
    for _, mode := range []string{"fake-5", "disorder", "split", "split-1"} {
        p, err := BuildPlan(TagPrefix+mode, "tcp", tls)
        if err != nil || !p.Applied || p.Cut != 1 || len(p.Fake) != 0 {
            t.Fatalf("SNI-less fallback %s: %+v: %v", mode, p, err)
        }
    }
    nonTLS := []byte("SSH-2.0\r\n")
    p, err := BuildPlan(TagPrefix+"split-1", "tcp", nonTLS)
    if err != nil || p.Applied { t.Fatalf("non-TLS fragmented: %+v %v", p, err) }
}

func TestOnePlannerForQUICVersionsAndUDP(t *testing.T) {
    for _, ver := range []struct{ first byte; ver []byte }{
        {0xc0, []byte{0,0,0,1}},
        {0xd0, []byte{0x6b,0x33,0x43,0xcf}},
    } {
        initial := make([]byte, 1200)
        initial[0] = ver.first
        copy(initial[1:5], ver.ver)
        p, err := BuildPlan(TagPrefix+"fake-5", "udp", initial)
        if err != nil || !p.Applied || len(p.Fake) != 1200 ||
            p.Repeats != 6 || p.TTL != 5 ||
            !bytes.Equal(initial[:64], p.Fake[:64]) {
            t.Fatalf("QUIC plan %+v: %v", p, err)
        }
        notFake, err := BuildPlan(TagPrefix+"split", "udp", initial)
        if err != nil || notFake.Applied { t.Fatal("split should not fake QUIC") }
    }
}

func TestUnixPlannerMatchesInProcessAndFailsClosed(t *testing.T) {
    path := filepath.Join(t.TempDir(), "planner.sock")
    ln, err := net.Listen("unix", path)
    if err != nil { t.Fatal(err) }
    t.Cleanup(func(){ _ = SetPlannerSocket(""); ln.Close() })
    replies := make(chan error, 1)
    go func() {
        conn, err := ln.Accept()
        if err != nil { replies <- err; return }
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(3*time.Second))
        var req Request
        if err := json.NewDecoder(conn).Decode(&req); err != nil { replies <- err; return }
        p, err := BuildPlan(req.Tag, req.Network, req.First)
        if err != nil { replies <- err; return }
        replies <- json.NewEncoder(conn).Encode(Response{Plan:p})
    }()
    if err := SetPlannerSocket(path); err != nil { t.Fatal(err) }
    hello := []byte{22, 3, 3, 0, 4, 1, 0, 0, 0}
    p, err := PlanFor(TagPrefix+"split-1", "tcp", hello)
    if err != nil || p.Cut != 1 || !p.Applied { t.Fatalf("unix planner: %+v %v", p, err) }
    if err := <-replies; err != nil { t.Fatal(err) }
    ln.Close()
    if _, err := PlanFor(TagPrefix+"split-1", "tcp", hello); err == nil {
        t.Fatal("Alpine planner outage must not fall back to direct traffic")
    }
    _ = SetPlannerSocket("")
    p, err = PlanFor(TagPrefix+"split-1", "tcp", hello)
    if err != nil || p.Cut != 1 { t.Fatal("non-Alpine build must use same shared planner") }
}
