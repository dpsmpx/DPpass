//go:build linux

package bridge

import (
    "errors"
    "io"
    "net"
    "path/filepath"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestInitialTCPCloseCancelsPlanner(t *testing.T) {
    path:=filepath.Join(t.TempDir(),"p.sock")
    listener,err:=net.ListenUnix("unix",&net.UnixAddr{Name:path,Net:"unix"})
    if err!=nil {t.Fatal(err)}
    defer listener.Close()
    _=listener.SetDeadline(time.Now().Add(3*time.Second))
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(path);err!=nil {t.Fatal(err)}
    defer zapret2.SetPlannerSocket(prev)
    outgoing,incoming:=tcpCopyPair(t)
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplit}}
    defer conn.Close()
    result:=make(chan error,1)
    hello:=[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    go func(){_,err:=conn.Write(hello);result<-err}()
    ipc,err:=listener.AcceptUnix()
    if err!=nil {t.Fatal(err)}
    defer ipc.Close()
    _=ipc.SetDeadline(time.Now().Add(3*time.Second))
    if _,err:=zapret2.ReadRequest(ipc);err!=nil {t.Fatal(err)}
    closed:=make(chan error,1)
    go func(){closed<-conn.Close()}()
    select {
    case err:=<-closed: if err!=nil {t.Fatal(err)}
    case <-time.After(time.Second):t.Fatal("full close waited for planner")
    }
    _=ipc.SetReadDeadline(time.Now().Add(time.Second))
    if n,err:=ipc.Read(make([]byte,1));n!=0 || !errors.Is(err,io.EOF) {t.Fatal("planner request not cancelled",n,err)}
    select {
    case err:=<-result:if err==nil {t.Fatal("cancelled write succeeded")}
    case <-time.After(time.Second):t.Fatal("write did not unblock")
    }
    _=incoming.SetReadDeadline(time.Now().Add(time.Second))
    if n,err:=incoming.Read(make([]byte,1));n!=0 || !errors.Is(err,io.EOF) {t.Fatal("bytes escaped cancellation",n,err)}
    if conn.initialReady.Load(){t.Fatal("cancelled write published readiness")}
    if n,err:=conn.Write([]byte("late"));n!=0 || err==nil {t.Fatal("write after close",n,err)}
}

func TestInitialTCPCloseDiscardsPending(t *testing.T) {
    outgoing,incoming:=tcpCopyPair(t)
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplitFirst}}
    // Install a pending partial record directly to make Close-before-flush deterministic.
    conn.pending=[]byte{22,3}
    if err:=conn.Close();err!=nil {t.Fatal(err)}
    _=incoming.SetReadDeadline(time.Now().Add(time.Second))
    if n,err:=incoming.Read(make([]byte,1));n!=0 || !errors.Is(err,io.EOF) {t.Fatal("full close flushed pending bytes",n,err)}
    if len(conn.pending)!=0 || !conn.firstDone {t.Fatal("buffer retained")}
    if n,err:=conn.Write([]byte{22,3});n!=0 || !errors.Is(err,net.ErrClosed) {t.Fatal("write after full close",n,err)}
}
