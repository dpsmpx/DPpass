//go:build linux

package bridge

import (
    "io"
    "net"
    "strings"
    "testing"
    "time"
)

func TestQUICMetricsAreBoundedAndDoNotExportDatagrams(t *testing.T) {
    a,b:=net.Pipe()
    defer a.Close()
    defer b.Close()
    _=a.SetDeadline(time.Now().Add(time.Second))
    _=b.SetDeadline(time.Now().Add(time.Second))
    first:=[]byte{0xc0,0,0,0,1,0,0} // public v1 Initial-shaped header
    peer:=[]byte{0xc0,0,0,0,1,0,0}
    done:=make(chan struct{})
    go func() {
        defer close(done)
        io.ReadFull(b,make([]byte,len(first)))
        _,_=b.Write(peer)
    }()
    remote:=&net.UDPAddr{IP:net.IPv4(8,8,8,8),Port:443}
    packets:=&matrixPacketConn{Conn:a,remote:remote}
    if _,err:=packets.WriteTo(first,remote);err!=nil {t.Fatal(err)}
    if _,_,err:=packets.ReadFrom(make([]byte,128));err!=nil {t.Fatal(err)}
    <-done
    out:=Zapret2HTTPSResult{Outcome:"quic_timeout_after_reply",
        Elapsed:time.Second,DnsFingerprint:"8020f565",DnsAnswers:8,
        IPIndex:0,Protocol:"quic",TLSStage:packets.failureStage(),ALPN:"-"}
    packets.metrics(&out)
    if out.QuicInitialTx!=1 || out.QuicPeerRx!=1 ||
        out.QuicMaxInitialBytes!=int32(len(first)) ||
        out.TLSStage!="quic_peer_initial_header" {
        t.Fatalf("incorrect public-header observations %+v",out)
    }
    wire:=string(out.Wire())
    if !strings.HasPrefix(wire,"v4\t") || len(strings.Split(wire,"\t"))!=17 ||
        strings.Contains(wire,"8.8.8.8") || strings.Contains(wire,"youtube") {
        t.Fatalf("unredacted or malformed v4 summary %q",wire)
    }
}
