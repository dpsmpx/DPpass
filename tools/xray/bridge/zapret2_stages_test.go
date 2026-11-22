//go:build linux

package bridge

import (
    "bytes"
    "context"
    "errors"
    "io"
    "net"
    "syscall"
    "testing"
    "time"
)

func TestZapret2DialErrorClassesAndTLSAlertHeader(t *testing.T) {
    for _, tc := range []struct { err error; index int }{
        {context.DeadlineExceeded, 1},
        {syscall.ECONNREFUSED, 2},
        {syscall.ENETUNREACH, 3},
        {errors.New("other"), 4},
    } {
        before := Zapret2Stages()
        recordZapret2DialFailure(tc.err)
        after := Zapret2Stages()
        if after[tc.index] < before[tc.index]+1 {
            t.Fatalf("error %v not classified at %d", tc.err, tc.index)
        }
    }
    for _, tc := range []struct { bytes []byte; want bool }{
        {[]byte{21,3,3,0,2,2,40}, true},
        {[]byte{22,3,3,0,2,2,40}, false},
        {[]byte{21,3,3,0,0}, false},
        {[]byte{21,3,3}, false},
    } {
        if got := isTLSAlertRecordHeader(tc.bytes); got != tc.want {
            t.Fatalf("TLS header %v = %v", tc.bytes, got)
        }
    }
}

func TestZapret2AddressFamilyDiagnosticsDoNotExposeIP(t *testing.T) {
    before := Zapret2Stages()
    recordZapret2DialSuccessFamily(net.ParseIP("192.0.2.1"))
    recordZapret2DialSuccessFamily(net.ParseIP("2001:db8::1"))
    recordZapret2DialSuccessFamily(nil)
    recordZapret2DialFailureWithIP(syscall.ENETUNREACH, net.ParseIP("192.0.2.2"))
    recordZapret2DialFailureWithIP(syscall.EHOSTUNREACH, net.ParseIP("2001:db8::2"))
    recordZapret2DialFailureWithIP(syscall.ENETUNREACH, nil)
    after := Zapret2Stages()
    for _, index := range []int{15,16,17,18,19,20} {
        if after[index] != before[index]+1 {
            t.Fatalf("family counter[%d] expected +1, before=%v after=%v", index, before, after)
        }
    }
    if after[3] < before[3]+3 { t.Fatal("unreachable total lost failures") }
    if zapret2AddressFamily(nil) != 0 ||
        zapret2AddressFamily(net.ParseIP("2001:db8::1")) != 6 ||
        zapret2AddressFamily(net.ParseIP("192.0.2.3")) != 4 {
        t.Fatal("wrong address family interpretation")
    }
}

func TestZapret2TCPStageEvidenceWithoutReply(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    hello := clientHello(t, "example.org")
    conn := &desyncConn{TCPConn: outgoing, mode: desyncMode{kind: desyncSplitFirst}}
    before := Zapret2Stages()
    if n, err := conn.Write(hello); n != len(hello) || err != nil {
        t.Fatalf("first write %d %v", n, err)
    }
    got := make([]byte, len(hello))
    _ = incoming.SetReadDeadline(time.Now().Add(2*time.Second))
    if _, err := io.ReadFull(incoming, got); err != nil { t.Fatal(err) }
    if !bytes.Equal(got, hello) { t.Fatal("instrumentation mutated ClientHello") }
    if err := conn.Close(); err != nil { t.Fatal(err) }
    after := Zapret2Stages()
    if after[5] < before[5]+1 || after[8] < before[8]+1 {
        t.Fatalf("expected TLS hello sent + no reply; before=%v after=%v", before, after)
    }
}

func TestZapret2TCPStageRecordsFirstTLSAlert(t *testing.T) {
    outgoing, incoming := tcpCopyPair(t)
    conn := &desyncConn{TCPConn: outgoing, mode: desyncMode{kind: desyncSplitFirst}}
    defer conn.Close()
    before := Zapret2Stages()
    hello := clientHello(t, "video.example.org")
    if n, err := conn.Write(hello); n != len(hello) || err != nil { t.Fatalf("hello %d %v", n, err) }
    got := make([]byte, len(hello))
    _ = incoming.SetReadDeadline(time.Now().Add(2*time.Second))
    if _, err := io.ReadFull(incoming, got); err != nil { t.Fatal(err) }
    alert := []byte{21,3,3,0,2,2,40}
    if _, err := incoming.Write(alert); err != nil { t.Fatal(err) }
    reply := make([]byte, len(alert))
    _ = conn.SetReadDeadline(time.Now().Add(2*time.Second))
    if _, err := io.ReadFull(conn, reply); err != nil { t.Fatal(err) }
    if !bytes.Equal(reply, alert) { t.Fatal("instrumentation mutated TLS alert") }
    after := Zapret2Stages()
    if after[7] < before[7]+1 || after[9] < before[9]+1 { t.Fatal("missing TCP reply/TLS alert evidence") }
}

func TestZapret2QUICStageEvidence(t *testing.T) {
    receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }
    defer receiver.Close()
    sock, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
    if err != nil { t.Fatal(err) }
    conn := &desyncUDPConn{UDPConn: sock, mode: desyncMode{kind: desyncPass}}
    defer conn.Close()
    before := Zapret2Stages()
    initial := make([]byte, 1200)
    initial[0], initial[4] = 0xc0, 1
    if n, err := conn.Write(initial); n != len(initial) || err != nil { t.Fatalf("initial %d %v", n, err) }
    buf := make([]byte, 1500)
    _ = receiver.SetReadDeadline(time.Now().Add(2*time.Second))
    n, addr, err := receiver.ReadFromUDP(buf)
    if err != nil || !bytes.Equal(buf[:n], initial) { t.Fatalf("QUIC Initial corrupted %d %v", n, err) }
    if _, err := receiver.WriteToUDP([]byte("QUIC reply"), addr); err != nil { t.Fatal(err) }
    _ = conn.SetReadDeadline(time.Now().Add(2*time.Second))
    n, err = conn.Read(buf)
    if err != nil || !bytes.Equal(buf[:n], []byte("QUIC reply")) { t.Fatalf("UDP reply corrupted %d %v", n, err) }
    after := Zapret2Stages()
    if after[11] < before[11]+1 || after[13] < before[13]+1 { t.Fatal("missing QUIC Initial/UDP reply evidence") }
}
