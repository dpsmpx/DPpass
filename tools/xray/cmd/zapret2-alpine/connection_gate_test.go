//go:build linux

package main

import (
    "io"
    "encoding/json"
    "net"
    "sync/atomic"
    "testing"
    "time"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
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
    for i:=0;i<limit;i++ {
        server,peer:=net.Pipe()
        defer peer.Close()
        if !gate.start(server,handler) {t.Fatal("available slot refused")}
        select {case <-entered:case <-time.After(time.Second):t.Fatal("worker did not start")}
    }
    server,peer:=net.Pipe()
    defer peer.Close()
    if gate.start(server,handler) {t.Fatal("overload admitted")}
    _ = peer.SetReadDeadline(time.Now().Add(time.Second))
    if _,err:=peer.Read(make([]byte,1));err!=io.EOF {t.Fatal("refused socket not closed",err)}
    if calls.Load()!=limit {t.Fatal("refused request started a handler")}
    select {case release<-struct{}{}:case <-time.After(time.Second):t.Fatal("worker did not release")}
    deadline:=time.Now().Add(time.Second)
    for len(gate.slots)==limit && time.Now().Before(deadline) {time.Sleep(time.Millisecond)}
    if len(gate.slots)!=limit-1 {t.Fatal("slot not released")}
    replacement,other:=net.Pipe()
    defer other.Close()
    if !gate.start(replacement,handler) {t.Fatal("released slot not reusable")}
    select {case <-entered:case <-time.After(time.Second):t.Fatal("replacement did not start")}
    if calls.Load()!=limit+1 {t.Fatal("unexpected handler count")}
}

func TestPlannerWorkerReleasesSlotAfterMalformedAndValidRequest(t *testing.T) {
    gate:=newConnectionGate(1)
    waitIdle:=func(){
        t.Helper()
        deadline:=time.Now().Add(time.Second)
        for len(gate.slots)!=0 && time.Now().Before(deadline) {time.Sleep(time.Millisecond)}
        if len(gate.slots)!=0 {t.Fatal("worker slot leaked")}
    }
    for _,malformed:=range []bool{true,false,true,false} {
        server,peer:=net.Pipe()
        if err:=peer.SetDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
        if !gate.start(server,handleConnection) {peer.Close();t.Fatal("idle gate refused")}
        if malformed {
            if _,err:=io.WriteString(peer,"invalid JSON\n");err!=nil {peer.Close();t.Fatal(err)}
            if _,err:=peer.Read(make([]byte,1));err!=io.EOF {peer.Close();t.Fatal("invalid request not closed",err)}
        } else {
            req:=zapret2.Request{Tag:zapret2.TagPrefix+"pass",Network:"tcp",First:[]byte("fixture")}
            if err:=json.NewEncoder(peer).Encode(req);err!=nil {peer.Close();t.Fatal(err)}
            var resp zapret2.Response
            if err:=json.NewDecoder(peer).Decode(&resp);err!=nil {peer.Close();t.Fatal(err)}
            if resp.Error!="" || resp.Plan.Applied || resp.Plan.Strategy!=req.Tag {
                peer.Close();t.Fatal("unexpected baseline response")
            }
        }
        peer.Close()
        waitIdle()
    }
}
