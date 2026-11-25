//go:build linux

package bridge

import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "bytes"
    "io"
    "net"
    "testing"
)

type copyOnlyReader struct{ io.Reader }

func tcpCopyPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
    t.Helper()
    listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = listener.Close() })
    accepted := make(chan *net.TCPConn, 1)
    failed := make(chan error, 1)
    go func() {
        conn, err := listener.AcceptTCP()
        if err != nil { failed <- err; return }
        accepted <- conn
    }()
    outgoing, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
    if err != nil { t.Fatal(err) }
    var incoming *net.TCPConn
    select {
    case incoming = <-accepted:
    case err = <-failed: t.Fatal(err)
    }
    t.Cleanup(func() { _ = outgoing.Close(); _ = incoming.Close() })
    return outgoing, incoming
}

// Regression: TCPConn implements io.ReaderFrom. Before the wrapper override,
// io.Copy from an ordinary reader went straight to the embedded socket,
// bypassing desyncConn.Write and any Alpine strategy.
func TestTCPReadFromCannotBypassClientHelloStrategy(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    hello := clientHello(t, "video.example.org")
    conn := &desyncConn{TCPConn: outgoing, mode: desyncMode{kind: desyncSplitFirst}}
    before := desyncApplied.Load()
    n, err := io.Copy(conn, copyOnlyReader{bytes.NewReader(hello)})
    if err != nil || n != int64(len(hello)) {
        t.Fatalf("io.Copy client hello: n=%d err=%v", n, err)
    }
    got := make([]byte, len(hello))
    if _, err := io.ReadFull(incoming, got); err != nil { t.Fatal(err) }
    if !bytes.Equal(got, hello) { t.Fatal("desync corrupted original ClientHello") }
    if desyncApplied.Load() <= before {
        t.Fatal("io.Copy bypassed Alpine TCP split-first write")
    }
}

// TCPConn also implements io.WriterTo: an Xray downstream copy could bypass
// desyncConn.Read and falsely report zero useful bytes to auto selection.
func TestTCPWriteToCountsDownloadedPayload(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    const host = "adaptive-copy-test.example.org"
    // Exercise actual selection so the socket carries the cache incarnation
    // captured under the selector lock, just like production connections.
    pick := zapret2Auto.chooseSocketLive(host, []string{"fake-5"}, localdpi.TLS)
    if pick.entryID == 0 || pick.flow.MethodID != "fake-5" {
        t.Fatal("failed to select a bound socket method")
    }
    conn := &desyncConn{TCPConn: outgoing}
    conn.adaptiveSelection.Store(pick)
    payload := bytes.Repeat([]byte("video-payload-"), 12000)
    sent := make(chan error, 1)
    go func() {
        _, err := incoming.Write(payload)
        if err == nil { err = incoming.Close() }
        sent <- err
    }()
    n, err := io.Copy(io.Discard, conn)
    if err != nil || n != int64(len(payload)) {
        t.Fatalf("io.Copy downstream n=%d err=%v", n, err)
    }
    if err := <-sent; err != nil { t.Fatal(err) }
    // A long-lived HTTP/2 stream must count before the connection closes.
    zapret2Auto.mu.Lock()
    earlyWinner := zapret2Auto.entries[host].preferred
    zapret2Auto.mu.Unlock()
    if earlyWinner != "fake-5" { t.Fatalf("streaming payload not observed before Close: %q", earlyWinner) }
    _ = conn.Close()
    if conn.received.Load() != int64(len(payload)) {
        t.Fatal("io.WriterTo bypassed observed downstream bytes")
    }
    zapret2Auto.mu.Lock()
    preferred := zapret2Auto.entries[host].preferred
    zapret2Auto.mu.Unlock()
    if preferred != "fake-5" { t.Fatalf("payload evidence not learned: %q", preferred) }
}
