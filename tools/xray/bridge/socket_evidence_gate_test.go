//go:build linux

package bridge

import (
    "bytes"
    "io"
    "net"
    "sync"
    "sync/atomic"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func TestSocketEvidenceGateOneTerminalObservation(t *testing.T) {
    pick:=zapret2Auto.newSocketPick("gate.example.test","pass",1,localdpi.TLS)
    var g socketEvidenceGate
    var delivered []localdpi.Evidence
    emit:=func(_ *adaptivePick,e localdpi.Evidence){delivered=append(delivered,e)}
    retain:=func(_ *adaptivePick){}
    if g.submit(pick,localdpi.SocketClose(0),false,emit) ||
        g.submit(nil,localdpi.SocketDownstream(100),false,emit) ||
        !g.retain(pick,retain) {t.Fatal("invalid observation consumed allowance")}
    if !g.submit(pick,localdpi.SocketFirstReplyTimeout(true,false,0),false,emit) ||
        g.retain(pick,retain) || g.submit(pick,localdpi.SocketDownstream(100),false,emit) ||
        g.submit(pick,localdpi.SocketClose(100),true,emit) {t.Fatal("multiple terminal labels")}
    if len(delivered)!=1 || delivered[0].Kind!=localdpi.FirstReplyTimeout {t.Fatal(delivered)}
}

func TestSocketEvidenceGateNeutralCloseAndSeal(t *testing.T) {
    pick:=zapret2Auto.newSocketPick("gate.example.test","pass",1,localdpi.TLS)
    emit:=func(_ *adaptivePick,_ localdpi.Evidence){t.Fatal("unexpected evidence")}
    for _,seal:=range []bool{false,true} {
        var g socketEvidenceGate
        if seal {g.seal()} else if g.submit(pick,localdpi.SocketClose(0),true,emit) {t.Fatal("neutral close learned")}
        if g.submit(pick,localdpi.SocketDownstream(100),false,emit) ||
            g.retain(pick,func(_ *adaptivePick){t.Fatal("late reachability")}) {t.Fatal("closed gate reused")}
    }
}

func TestSocketEvidenceGateConcurrentClaims(t *testing.T) {
    pick:=zapret2Auto.newSocketPick("gate.example.test","pass",1,localdpi.TLS)
    var g socketEvidenceGate
    var writes atomic.Int32
    var wg sync.WaitGroup
    for i:=0;i<64;i++ {
        wg.Add(1)
        go func(){
            defer wg.Done()
            g.submit(pick,localdpi.SocketDownstream(100),false,func(_ *adaptivePick,_ localdpi.Evidence){writes.Add(1)})
        }()
    }
    wg.Wait()
    if writes.Load()!=1 {t.Fatal("duplicate learning",writes.Load())}
}

func TestSocketLateReplyAfterTimeout(t *testing.T) {
    for _,transport:=range []localdpi.Transport{localdpi.TLS,localdpi.QUIC} {
        key:="late-reply.example.test"
        if transport==localdpi.QUIC {key="udp:"+key}
        zapret2Auto.mu.Lock()
        old,exists:=zapret2Auto.entries[key]
        delete(zapret2Auto.entries,key)
        zapret2Auto.mu.Unlock()
        func(){
            defer func(){
                zapret2Auto.mu.Lock()
                defer zapret2Auto.mu.Unlock()
                if exists {zapret2Auto.entries[key]=old} else {delete(zapret2Auto.entries,key)}
            }()
            pick:=zapret2Auto.chooseSocketLive(key,transport)
            if pick.flow.MethodID!="pass" || pick.entryID==0 {t.Fatal("expected baseline selection")}
            zapret2Auto.mu.Lock()
            entry:=zapret2Auto.entries[key]
            entry.preferred="pass"
            zapret2Auto.mu.Unlock()
            var conn net.Conn
            var send func([]byte) error
            if transport==localdpi.TLS {
                out,peer:=tcpCopyPair(t)
                c:=&desyncConn{TCPConn:out,firstDone:true}
                c.adaptiveSelection.Store(pick)
                c.stageHelloSent.Store(true)
                conn=c
                send=func(b []byte)error{_,err:=peer.Write(b);return err}
            } else {
                peer,err:=net.ListenUDP("udp4",&net.UDPAddr{IP:net.IPv4(127,0,0,1)})
                if err!=nil {t.Fatal(err)}
                defer peer.Close()
                out,err:=net.DialUDP("udp4",nil,peer.LocalAddr().(*net.UDPAddr))
                if err!=nil {t.Fatal(err)}
                c:=&desyncUDPConn{UDPConn:out}
                c.adaptiveSelection.Store(pick)
                c.stageInitialSent.Store(true)
                conn=c
                send=func(b []byte)error{_,err:=peer.WriteToUDP(b,out.LocalAddr().(*net.UDPAddr));return err}
            }
            defer conn.Close()
            if err:=conn.SetReadDeadline(time.Now().Add(-time.Millisecond));err!=nil {t.Fatal(err)}
            if _,err:=conn.Read(make([]byte,1));!isZapret2Timeout(err) {t.Fatal("expected timeout",err)}
            zapret2Auto.mu.Lock()
            stalls,weak,plain:=entry.stalls["pass"],entry.weakFailures,entry.plainReachable
            zapret2Auto.mu.Unlock()
            if stalls!=1 || weak!=1 || plain {t.Fatal("timeout evidence missing",stalls,weak,plain)}
            if err:=conn.SetReadDeadline(time.Now().Add(3*time.Second));err!=nil {t.Fatal(err)}
            data:=bytes.Repeat([]byte{0x41},8192)
            for remaining:=adaptivePayloadThreshold;remaining>0;remaining-=len(data) {
                if err:=send(data);err!=nil {t.Fatal(err)}
                got:=make([]byte,len(data))
                if _,err:=io.ReadFull(conn,got);err!=nil || !bytes.Equal(data,got) {t.Fatal("late bytes lost",err)}
            }
            if err:=conn.Close();err!=nil {t.Fatal(err)}
            zapret2Auto.mu.Lock()
            afterStalls,afterWeak,afterPlain:=entry.stalls["pass"],entry.weakFailures,entry.plainReachable
            zapret2Auto.mu.Unlock()
            if afterStalls!=stalls || afterWeak!=weak || afterPlain!=plain {
                t.Fatal("late reply retrained flow",transport,afterStalls,afterWeak,afterPlain)
            }
        }()
    }
}
