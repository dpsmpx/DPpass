//go:build linux

package bridge

import (
    "bytes"
    "io"
    "path/filepath"
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


// Real TCP sockets: a large initial Write must not be rejected by the
// 32 KiB IPC limit, nor lose or duplicate the data after the first record.
func TestLargeFirstTCPWritePreservesTail(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    hello:=clientHello(t,"example.test")
    header:=[]byte("POST / HTTP/1.1\r\nHost: example.test\r\nContent-Length: 65536\r\n\r\n")
    tail:=bytes.Repeat([]byte{0x7c},65536)
    for _,tc:=range []struct{
        name string
        mode desyncMode
        prefix []byte
        want []byte
        diagnostic bool
        applied bool
    }{
        {"tls",desyncMode{kind:desyncTLSRecordSplit},hello,nil,false,true},
        {"http-split",desyncMode{kind:desyncSplit},header,header,false,true},
        {"http-rewrite",desyncMode{kind:desyncHTTPHostCase},header,
            bytes.Replace(header,[]byte("\r\nHost:"),[]byte("\r\nhOsT:"),1),true,true},
        {"raw",desyncMode{kind:desyncSplit},[]byte("SSH-2.0-example\r\n"),[]byte("SSH-2.0-example\r\n"),false,false},
    } {
        t.Run(tc.name,func(t *testing.T){
            for _,fragmented:=range []bool{false,true} {
                outgoing,incoming:=tcpCopyPair(t)
                request:=&diagnosticRequestCounters{}
                conn:=&desyncConn{TCPConn:outgoing,mode:tc.mode,diagnostic:tc.diagnostic,request:request}
                _=outgoing.SetWriteDeadline(time.Now().Add(3*time.Second))
                _=incoming.SetReadDeadline(time.Now().Add(3*time.Second))
                expectedPrefix:=tc.want
                if expectedPrefix==nil {
                    p,err:=zapret2.BuildPlan(zapret2.TagPrefix+"tlsrec-split","tcp",tc.prefix)
                    if err!=nil || !p.Applied {t.Fatal("TLS fixture",err)}
                    expectedPrefix=p.Rewrite
                }
                first:=append(bytes.Clone(tc.prefix),tail...)
                expected:=append(bytes.Clone(expectedPrefix),tail...)
                before,_:=DesyncStats()
                if fragmented {
                    n,err:=conn.Write(first[:2])
                    if n!=2 || err!=nil {t.Fatal(n,err)}
                    first=first[2:]
                }
                n,err:=conn.Write(first)
                if n!=len(first) || err!=nil {t.Fatal("large write",n,err)}
                got:=make([]byte,len(expected))
                if _,err=io.ReadFull(incoming,got);err!=nil || !bytes.Equal(got,expected) {
                    t.Fatal("large write corrupted",err)
                }
                conn.writeMu.Lock()
                done,remaining:=conn.firstDone,len(conn.pending)
                conn.writeMu.Unlock()
                if !done || remaining!=0 {t.Fatal("initial buffer retained")}
                after,_:=DesyncStats()
                if tc.diagnostic {
                    applied,skipped:=request.finish()
                    if applied!=1 || skipped!=0 || after!=before {t.Fatal("wrong diagnostic accounting")}
                } else if tc.applied && after!=before+1 {t.Fatal("method skipped on large input")}
                if err:=conn.Close();err!=nil {t.Fatal(err)}
                var extra [1]byte
                if n,err:=incoming.Read(extra[:]);n!=0 || err!=io.EOF {t.Fatal("unexpected extra bytes",n,err)}
            }
        })
    }
}

func TestLargeFirstTCPWritePlannerFailureDoesNotSendTail(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    outgoing,incoming:=tcpCopyPair(t)
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplit}}
    first:=append([]byte("POST / HTTP/1.1\r\nHost: example.test\r\n\r\n"),bytes.Repeat([]byte("x"),65536)...)
    if n,err:=conn.Write(first);err==nil || n!=0 {t.Fatal("planner failure did not stop first write",n,err)}
    if n,err:=conn.Write([]byte("retry"));err==nil || n!=0 {t.Fatal("planner failure was not sticky",n,err)}
    _=conn.Close()
    _=incoming.SetReadDeadline(time.Now().Add(3*time.Second))
    var b [1]byte
    if n,err:=incoming.Read(b[:]);n!=0 || err!=io.EOF {t.Fatal("bytes escaped failed planner",n,err)}
}
