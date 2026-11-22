//go:build linux

package zapret2

import (
    "bytes"
    "encoding/json"
    "encoding/binary"
    "crypto/tls"
    "io"
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


// TLS-record splitting must preserve each ClientHello handshake byte and all
// following records. A second TLS header is only an encoding change, not a
// change to the certificate, SNI, or encrypted application data.
func tlsClientHelloFixture(t *testing.T, name string) []byte {
    t.Helper()
    a, b := net.Pipe()
    defer a.Close()
    defer b.Close()
    go func() { _ = tls.Client(a, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake() }()
    header := make([]byte, 5)
    if _, err := io.ReadFull(b, header); err != nil { t.Fatal(err) }
    body := make([]byte, int(binary.BigEndian.Uint16(header[3:5])))
    if _, err := io.ReadFull(b, body); err != nil { t.Fatal(err) }
    return append(header, body...)
}

func TestCombinedTLSRecordAndTCPSplitPreservesHandshake(t *testing.T) {
    original := tlsClientHelloFixture(t, "r1.googlevideo.com")
    trailer := []byte{23, 3, 3, 0, 1, 0x55} // untouched following TLS record
    combined := append(bytes.Clone(original), trailer...)
    p, err := BuildPlan(TagPrefix+"tlsrec-split", "tcp", combined)
    if err != nil || !p.Applied || len(p.Fake) != 0 || len(p.Rewrite) != len(combined)+5 {
        t.Fatalf("combined TLS plan: %+v: %v", p, err)
    }
    if p.Cut < 9 || p.Cut >= len(p.Rewrite)-5 { t.Fatal("invalid split position", p.Cut) }
    firstLen := int(binary.BigEndian.Uint16(p.Rewrite[3:5]))
    secondLen := int(binary.BigEndian.Uint16(p.Rewrite[p.Cut+3:p.Cut+5]))
    if p.Cut != 5+firstLen || firstLen+secondLen != len(original)-5 {
        t.Fatalf("invalid record framing: first=%d second=%d cut=%d", firstLen, secondLen, p.Cut)
    }
    if !bytes.Equal(p.Rewrite[:3], original[:3]) ||
        !bytes.Equal(p.Rewrite[p.Cut:p.Cut+3], original[:3]) {
        t.Fatal("fragment record headers changed TLS type/version")
    }
    recovered := append(bytes.Clone(p.Rewrite[5:p.Cut]), p.Rewrite[p.Cut+5:p.Cut+5+secondLen]...)
    if !bytes.Equal(recovered, original[5:]) {
        t.Fatal("fragmented TLS records changed the handshake bytes")
    }
    if !bytes.Equal(p.Rewrite[p.Cut+5+secondLen:], trailer) {
        t.Fatal("trailing TLS records were changed")
    }
    // If a TLS record is incomplete, do not rewrite it or invent fake bytes.
    for _, incomplete := range [][]byte{original[:8], original[:30], original[:len(original)-1]} {
        q, err := BuildPlan(TagPrefix+"tlsrec-split", "tcp", incomplete)
        if err != nil || q.Applied || len(q.Rewrite) != 0 {
            t.Fatalf("incomplete TLS must not be rewritten: %+v: %v", q, err)
        }
    }
    for _, unrecognized := range [][]byte{
        []byte("GET / HTTP/1.1\\r\\nHost: example.org\\r\\n\\r\\n"),
        []byte("SSH-2.0-test"),
    } {
        q, err := BuildPlan(TagPrefix+"tlsrec-split", "tcp", unrecognized)
        if err != nil || q.Applied || len(q.Rewrite) != 0 {
            t.Fatalf("unrelated TCP was modified: %+v: %v", q, err)
        }
    }
}
