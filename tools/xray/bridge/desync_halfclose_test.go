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

func TestTCPHalfCloseFlushesAcceptedPartialFirstWrite(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    for _,tc:=range []struct{name string;mode desyncKind;data []byte}{
        {"tls",desyncSplitFirst,[]byte{22,3}},
        {"http",desyncHTTPHostCase,[]byte("POST / HTTP/1.1\r\nHost: example")},
    } {
        t.Run(tc.name,func(t *testing.T){
            outgoing,incoming:=tcpCopyPair(t)
            deadline:=time.Now().Add(3*time.Second)
            _=outgoing.SetDeadline(deadline)
            _=incoming.SetDeadline(deadline)
            counters:=&diagnosticRequestCounters{}
            conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:tc.mode},diagnostic:true,request:counters}
            defer conn.Close()
            if n,err:=conn.Write(tc.data);err!=nil || n!=len(tc.data) {t.Fatal(n,err)}
            if err:=conn.CloseWrite();err!=nil {t.Fatal(err)}
            got,err:=io.ReadAll(incoming)
            if err!=nil || !bytes.Equal(got,tc.data) {t.Fatal("accepted bytes lost before FIN",got,err)}
            if n,err:=conn.Write([]byte("late"));n!=0 || err==nil {t.Fatal("write after FIN accepted",n,err)}
            if _,err:=incoming.Write([]byte("reply"));err!=nil {t.Fatal(err)}
            reply:=make([]byte,5)
            if _,err:=io.ReadFull(conn,reply);err!=nil || string(reply)!="reply" {
                t.Fatal("read side closed",err)
            }
            conn.writeMu.Lock()
            done,pending,timer:=conn.firstDone,len(conn.pending),conn.pendingTimer
            conn.writeMu.Unlock()
            if !done || pending!=0 || timer!=nil {t.Fatal("pending state after FIN")}
            applied,_:=counters.finish()
            if applied!=0 {t.Fatal("incomplete input modified")}
        })
    }
}

func TestTCPEmptyHalfCloseDoesNotAcceptNewBufferedData(t *testing.T) {
    outgoing,incoming:=tcpCopyPair(t)
    _=incoming.SetDeadline(time.Now().Add(3*time.Second))
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplitFirst}}
    defer conn.Close()
    if err:=conn.CloseWrite();err!=nil {t.Fatal(err)}
    if n,err:=conn.Write([]byte{22,3});n!=0 || err==nil {t.Fatal("buffered after FIN",n,err)}
    if got,err:=io.ReadAll(incoming);err!=nil || len(got)!=0 {t.Fatal(got,err)}
}

func TestTCPHalfCloseKeepsPlannerFailureSticky(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    outgoing,incoming:=tcpCopyPair(t)
    _=incoming.SetDeadline(time.Now().Add(3*time.Second))
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncMultiSplit},diagnostic:true,request:&diagnosticRequestCounters{}}
    defer conn.Close()
    if n,err:=conn.Write([]byte{22,3});n!=2 || err!=nil {t.Fatal(n,err)}
    if err:=conn.CloseWrite();err==nil {t.Fatal("failed planner hidden")}
    if n,err:=conn.Write([]byte("retry"));n!=0 || err==nil {t.Fatal("failed planner retried",n,err)}
    if got,err:=io.ReadAll(incoming);err!=nil || len(got)!=0 {t.Fatal("bytes escaped failed planner",got,err)}
}
