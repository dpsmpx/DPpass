//go:build linux

package bridge

import (
    "bytes"
    "io"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

// The real Android TLS stack can issue several writes before completing its
// ClientHello. The strategy must see the complete record rather than consume
// its one-shot decision on the first two bytes.
func TestFragmentedClientHelloUsesCompleteFirstRecord(t *testing.T) {
    hello := clientHello(t, "r1.googlevideo.com")
    if len(hello) < 100 { t.Fatal("unexpectedly short TLS fixture") }
    for _, tc := range []struct {
        name string
        mode desyncMode
        expected []byte
    }{
        {"tcp-sni-split", desyncMode{kind: desyncSplit}, hello},
        {"tls-record-and-tcp-split", desyncMode{kind: desyncTLSRecordSplit}, nil},
    } {
        t.Run(tc.name, func(t *testing.T) {
            outgoing, incoming := tcpCopyPair(t)
            conn := &desyncConn{TCPConn: outgoing, mode: tc.mode}
            t.Cleanup(func() { _ = conn.Close() })
            expected := tc.expected
            if expected == nil {
                p, err := zapret2.BuildPlan(zapret2.TagPrefix+"tlsrec-split", "tcp", hello)
                if err != nil || !p.Applied { t.Fatalf("no TLS record plan: %v", err) }
                expected = p.Rewrite
            }
            before := desyncApplied.Load()
            for _, part := range [][]byte{hello[:2], hello[2:7], hello[7:20], hello[20:80], hello[80:]} {
                n, err := conn.Write(part)
                if err != nil || n != len(part) { t.Fatalf("fragment write: n=%d err=%v", n, err) }
            }
            _ = incoming.SetReadDeadline(time.Now().Add(3 * time.Second))
            got := make([]byte, len(expected))
            if _, err := io.ReadFull(incoming, got); err != nil { t.Fatal(err) }
            if !bytes.Equal(got, expected) { t.Fatal("fragmented ClientHello was corrupted or not correctly desynchronized") }
            if desyncApplied.Load() <= before { t.Fatal("fragmented ClientHello did not receive its intended strategy") }
            if len(conn.pending) != 0 || !conn.firstDone { t.Fatal("first-record buffer was not released") }
        })
    }
}

// If the caller starts reading before finishing its first TLS record, flush
// the accepted bytes instead of waiting forever for a second Write.
func TestFragmentedHelloReadFlushAvoidsDeadlock(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    conn := &desyncConn{TCPConn: outgoing, mode: desyncMode{kind: desyncSplitFirst}}
    defer conn.Close()
    hello := clientHello(t, "video.example.org")
    if n, err := conn.Write(hello[:2]); err != nil || n != 2 {
        t.Fatalf("first fragment: %d %v", n, err)
    }
    result := make(chan error, 1)
    go func() {
        buf := make([]byte, 1)
        _, err := conn.Read(buf)
        result <- err
    }()
    first := make([]byte, 2)
    _ = incoming.SetReadDeadline(time.Now().Add(3 * time.Second))
    if _, err := io.ReadFull(incoming, first); err != nil { t.Fatal(err) }
    if !bytes.Equal(first, hello[:2]) { t.Fatal("partial record changed") }
    if _, err := incoming.Write([]byte{1}); err != nil { t.Fatal(err) }
    select {
    case err := <-result:
        if err != nil { t.Fatal(err) }
    case <-time.After(3 * time.Second):
        t.Fatal("read blocked with pending ClientHello")
    }
    if n, err := conn.Write(hello[2:]); err != nil || n != len(hello)-2 {
        t.Fatalf("later fragment: %d %v", n, err)
    }
    tail := make([]byte, len(hello)-2)
    if _, err := io.ReadFull(incoming, tail); err != nil { t.Fatal(err) }
    if !bytes.Equal(tail, hello[2:]) { t.Fatal("remaining fragment changed") }
}

// Even when the application never writes the remaining ClientHello, bounded
// buffering must transmit its accepted bytes and release resources.
func TestIncompleteFirstTLSRecordHasBoundedFlush(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    conn := &desyncConn{TCPConn: outgoing, mode: desyncMode{kind: desyncSplitFirst}}
    defer conn.Close()
    fragment := []byte{22, 3, 3, 0, 64, 1, 0, 0, 60}
    if n, err := conn.Write(fragment); err != nil || n != len(fragment) {
        t.Fatalf("accepted fragment: %d %v", n, err)
    }
    got := make([]byte, len(fragment))
    _ = incoming.SetReadDeadline(time.Now().Add(3 * time.Second))
    if _, err := io.ReadFull(incoming, got); err != nil { t.Fatal(err) }
    if !bytes.Equal(got, fragment) { t.Fatal("timeout fallback corrupted incomplete ClientHello") }
    conn.writeMu.Lock()
    done, remaining := conn.firstDone, len(conn.pending)
    conn.writeMu.Unlock()
    if !done || remaining != 0 { t.Fatalf("buffer still active after timer: done=%t pending=%d", done, remaining) }
}
