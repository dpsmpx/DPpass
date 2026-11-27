//go:build linux

package bridge

import (
    "bytes"
    "io"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestMultiSplitProtectedTCPAdapterPreservesStream(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    outgoing,incoming:=tcpCopyPair(t)
    counters:=&diagnosticRequestCounters{}
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncMultiSplit},diagnostic:true,request:counters}
    defer conn.Close()
    hello:=clientHello(t,"example.test")
    before,_:=DesyncStats()
    for _,part:=range [][]byte{hello[:2],hello[2:]} {
        if n,err:=conn.Write(part);err!=nil || n!=len(part) {t.Fatal(n,err)}
    }
    _=incoming.SetReadDeadline(time.Now().Add(3*time.Second))
    got:=make([]byte,len(hello))
    if _,err:=io.ReadFull(incoming,got);err!=nil || !bytes.Equal(got,hello) {t.Fatal("stream changed",err)}
    applied,skipped:=counters.finish()
    after,_:=DesyncStats()
    if applied!=1 || skipped!=0 || before!=after {t.Fatal("diagnostic accounting",applied,skipped)}
}
