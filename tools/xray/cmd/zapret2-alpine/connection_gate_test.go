//go:build linux

package main

import (
    "io"
    "net"
    "sync/atomic"
    "testing"
    "time"
)

func TestConnectionGateLimitsAndRecovers(t *testing.T) {
    const limit=2
    gate:=newConnectionGate(limit)
    entered:=make(chan struct{},limit)
    release:=make(chan struct{})
    defer close(release)
    var calls atomic.Int32
    handler:=func(_ net.Conn){
        calls.Add(1)
        entered<-struct{}{}
        <-release
    }
    peers:=make([]net.Conn,0,limit)
    for i:=0;i<limit;i++ {
        server,peer:=net.Pipe()
        defer peer.Close()
        peers=append(peers,peer)
        if !gate.start(server,handler) {t.Fatal("available slot refused")}
        select {case <-entered:case <-time.After(time.Second):t.Fatal("worker did not start")}
    }
    server,peer:=net.Pipe()
    defer peer.Close()
    if gate.start(server,handler) {t.Fatal("overload admitted")}
    _ = peer.SetReadDeadline(time.Now().Add(time.Second))
    if _,err:=peer.Read(make([]byte,1));err!=io.EOF {t.Fatal("refused socket not closed",err)}
    if calls.Load()!=limit {t.Fatal("refused request started a handler")}
    release<-struct{}{}
    deadline:=time.Now().Add(time.Second)
    for len(gate.slots)==limit && time.Now().Before(deadline) {time.Sleep(time.Millisecond)}
    if len(gate.slots)!=limit-1 {t.Fatal("slot not released")}
    replacement,other:=net.Pipe()
    defer other.Close()
    if !gate.start(replacement,handler) {t.Fatal("released slot not reusable")}
    select {case <-entered:case <-time.After(time.Second):t.Fatal("replacement did not start")}
    if calls.Load()!=limit+1 {t.Fatal("unexpected handler count")}
}
