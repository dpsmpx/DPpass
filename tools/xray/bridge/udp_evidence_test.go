//go:build linux

package bridge

import (
    "bytes"
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
