//go:build linux

package bridge

import (
    "bytes"
    "errors"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "net"
    "testing"
    "time"
)

func TestUDPSelectionPublishedOnlyAfterSuccessfulInitial(t *testing.T) {
    for _,closed:=range []bool{false,true} {
        receiver,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
        if err!=nil {t.Fatal(err)}
        t.Cleanup(func(){_ = receiver.Close()})
        client,err:=net.DialUDP("udp4",nil,receiver.LocalAddr().(*net.UDPAddr))
        if err!=nil {t.Fatal(err)}
        t.Cleanup(func(){_ = client.Close()})
        const host="udp-evidence.example.test"
        key:=canonicalAdaptiveKey("udp:"+host)
        zapret2Auto.mu.Lock()
        old,exists:=zapret2Auto.entries[key]
        zapret2Auto.entries[key]=&adaptiveEntry{preferred:"pass"}
        zapret2Auto.mu.Unlock()
        func(){
            defer func(){
                zapret2Auto.mu.Lock()
                defer zapret2Auto.mu.Unlock()
                if exists {zapret2Auto.entries[key]=old} else {delete(zapret2Auto.entries,key)}
            }()
            c:=&desyncUDPConn{UDPConn:client,host:host,mode:desyncMode{kind:desyncAuto}}
            initial:=make([]byte,1200)
            initial[0],initial[4]=0xc0,1
            if closed {
                if err:=client.Close();err!=nil {t.Fatal(err)}
            }
            n,err:=c.Write(initial)
            if c.chosen==nil || c.chosen.flow.MethodID!="pass" {t.Fatal("choice not retained")}
            if closed {
                if err==nil || c.adaptiveSelection.Load()!=nil || c.stageInitialSent.Load() {
                    t.Fatal("failed write published evidence")
                }
                return
            }
            if err!=nil || n!=len(initial) || c.adaptiveSelection.Load()!=c.chosen || !c.stageInitialSent.Load() {
                t.Fatal("successful write missing evidence",n,err)
            }
            if err:=receiver.SetReadDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
            got:=make([]byte,1500)
            n,err=receiver.Read(got)
            if err!=nil || !bytes.Equal(got[:n],initial) {t.Fatal("baseline payload changed",err)}
        }()
    }
}

func TestUDPPreInitialReplyIsNotAttributedToLaterSelection(t *testing.T) {
    receiver,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
    if err!=nil {t.Fatal(err)}
    defer receiver.Close()
    client,err:=net.DialUDP("udp4",nil,receiver.LocalAddr().(*net.UDPAddr))
    if err!=nil {t.Fatal(err)}
    defer client.Close()
    if err:=client.SetDeadline(time.Now().Add(2*time.Second));err!=nil {t.Fatal(err)}
    if err:=receiver.SetDeadline(time.Now().Add(2*time.Second));err!=nil {t.Fatal(err)}
    const host="udp-preinitial.example.test"
    key:=canonicalAdaptiveKey("udp:"+host)
    zapret2Auto.mu.Lock()
    old,exists:=zapret2Auto.entries[key]
    zapret2Auto.entries[key]=&adaptiveEntry{preferred:"pass"}
    zapret2Auto.mu.Unlock()
    defer func(){
        zapret2Auto.mu.Lock()
        defer zapret2Auto.mu.Unlock()
        if exists {zapret2Auto.entries[key]=old} else {delete(zapret2Auto.entries,key)}
    }()
    c:=&desyncUDPConn{UDPConn:client,host:host,mode:desyncMode{kind:desyncAuto}}
    buf:=make([]byte,32768)
    earlier:=bytes.Repeat([]byte{0x41},16384)
    if _,err:=receiver.WriteToUDP(earlier,client.LocalAddr().(*net.UDPAddr));err!=nil {t.Fatal(err)}
    n,err:=c.Read(buf)
    if err!=nil || !bytes.Equal(buf[:n],earlier) {t.Fatal("pre-Initial data not delivered",err)}
    if c.received.Load()!=0 || !c.preInitialReply.Load() || c.stageFirstReply.Load() {
        t.Fatal("pre-Initial bytes entered method evidence")
    }
    initial:=make([]byte,1200)
    initial[0],initial[4]=0xc0,1
    if n,err:=c.Write(initial);err!=nil || n!=len(initial) {t.Fatal("Initial write failed",n,err)}
    if _,_,err:=receiver.ReadFromUDP(buf);err!=nil {t.Fatal(err)}
    if c.adaptiveSelection.Load()==nil {t.Fatal("completed baseline not published")}
    if err:=client.SetReadDeadline(time.Now().Add(-time.Millisecond));err!=nil {t.Fatal(err)}
    if _,err:=c.Read(buf);!isZapret2Timeout(err) {t.Fatal("expected timeout",err)}
    zapret2Auto.mu.Lock()
    stalls:=zapret2Auto.entries[key].stalls["pass"]
    zapret2Auto.mu.Unlock()
    if stalls!=0 {t.Fatal("ambiguous pre-Initial reply allowed negative training")}
    if err:=client.SetReadDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
    later:=[]byte("later reply")
    if _,err:=receiver.WriteToUDP(later,client.LocalAddr().(*net.UDPAddr));err!=nil {t.Fatal(err)}
    n,err=c.Read(buf)
    if err!=nil || !bytes.Equal(buf[:n],later) || c.received.Load()!=int64(len(later)) ||
        !c.stageFirstReply.Load() {t.Fatal("post-Initial evidence incorrect",n,err)}
    if err:=c.Close();err!=nil {t.Fatal(err)}
}

func TestUDPCompletedActionAccounting(t *testing.T) {
    liveA,liveS:=DesyncStats()
    diagA,diagS:=diagnosticDesyncStats()
    for _,tc:=range []struct{written int;err error;wantApplied bool}{
        {1200,nil,true},{1199,nil,false},{0,errors.New("write failed"),false},
        {1200,errors.New("write failed"),false},
    } {
        request:=&diagnosticRequestCounters{}
        c:=&desyncUDPConn{diagnostic:true,request:request}
        c.recordCompletedUDPAction(1200,tc.written,tc.err)
        a,s:=request.finish()
        if tc.wantApplied && (a!=1 || s!=0) || !tc.wantApplied && (a!=0 || s!=1) {
            t.Fatal("incorrect completed-action accounting",tc,a,s)
        }
    }
    a,s:=DesyncStats()
    da,ds:=diagnosticDesyncStats()
    if a!=liveA || s!=liveS || da!=diagA+1 || ds!=diagS+3 {
        t.Fatal("incorrect process counters")
    }
}

func TestDiagnosticUDPEvidenceCannotMutateLiveSelector(t *testing.T) {
    for _,tc:=range []struct{name string;timeout bool;payload int}{
        {"first-reply",false,1},
        {"large-downstream",false,adaptivePayloadThreshold+1},
        {"timeout",true,0},
    } {
        t.Run(tc.name,func(t *testing.T){
            const key="udp:diagnostic-isolation.example.test"
            zapret2Auto.mu.Lock()
            old,exists:=zapret2Auto.entries[key]
            delete(zapret2Auto.entries,key)
            zapret2Auto.mu.Unlock()
            t.Cleanup(func(){
                zapret2Auto.mu.Lock()
                defer zapret2Auto.mu.Unlock()
                if exists {zapret2Auto.entries[key]=old} else {delete(zapret2Auto.entries,key)}
            })
            _=zapret2Auto.chooseSocketLive(key,localdpi.QUIC)
            zapret2Auto.mu.Lock()
            entry:=zapret2Auto.entries[key]
            entry.preferred="pass"
            entry.plainReachable=false
            entry.weakFailures=1
            generation:=zapret2Auto.generation
            zapret2Auto.mu.Unlock()
            pick:=boundTestSocketPick(key,"pass",generation,localdpi.QUIC)
            if pick.entryID==0 {t.Fatal("test selection unbound")}
            peer,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
            if err!=nil {t.Fatal(err)}
            defer peer.Close()
            client,err:=net.DialUDP("udp4",nil,peer.LocalAddr().(*net.UDPAddr))
            if err!=nil {t.Fatal(err)}
            c:=&desyncUDPConn{UDPConn:client,diagnostic:true}
            defer c.Close()
            c.adaptiveSelection.Store(pick)
            c.stageInitialSent.Store(true)
            before:=Zapret2Stages()
            if err:=client.SetDeadline(time.Now().Add(3*time.Second));err!=nil {t.Fatal(err)}
            if err:=peer.SetDeadline(time.Now().Add(3*time.Second));err!=nil {t.Fatal(err)}
            buf:=make([]byte,16384)
            if tc.timeout {
                if err:=client.SetReadDeadline(time.Now().Add(-time.Millisecond));err!=nil {t.Fatal(err)}
                if _,err:=c.Read(buf);!isZapret2Timeout(err) {t.Fatal("expected timeout",err)}
            } else {
                for remaining:=tc.payload;remaining>0; {
                    size:=min(remaining,len(buf))
                    data:=bytes.Repeat([]byte{0x41},size)
                    if _,err:=peer.WriteToUDP(data,client.LocalAddr().(*net.UDPAddr));err!=nil {t.Fatal(err)}
                    n,err:=c.Read(buf)
                    if err!=nil || n!=size || !bytes.Equal(buf[:n],data) {t.Fatal("data changed",err)}
                    remaining-=n
                }
                if c.received.Load()!=int64(tc.payload) {t.Fatal("lost diagnostic byte counts")}
            }
            if err:=c.Close();err!=nil {t.Fatal(err)}
            zapret2Auto.mu.Lock()
            plain,weak,preferred,stalls:=entry.plainReachable,entry.weakFailures,entry.preferred,len(entry.stalls)
            zapret2Auto.mu.Unlock()
            if plain || weak!=1 || preferred!="pass" || stalls!=0 {
                t.Fatal("diagnostic mutated live selector",plain,weak,preferred,stalls)
            }
            if before!=Zapret2Stages() {t.Fatal("diagnostic mutated live stage counters")}
        })
    }
}
