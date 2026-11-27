//go:build linux

package bridge

import (
    "bytes"
    "io"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func TestFirstReplyHeaderFragmentation(t *testing.T) {
    alert:=[]byte{21,3,3,0,2,2,40}
    for split:=1;split<5;split++ {
        var h firstReplyHeader
        if h.observe(alert[:split])!=replyPending ||
            h.observe(alert[split:])!=replyAlert ||
            h.observe(alert)!=replyPending {t.Fatal("split alert",split)}
    }
    for _,b:=range [][]byte{[]byte("reply"),{21,2,3,0,2},{21,3,3,0,0},{22,3,3,0,4,2}} {
        var h firstReplyHeader
        if h.observe(b)!=replyOther || h.observe(b)!=replyPending {t.Fatal("non-alert classification")}
    }
    var h firstReplyHeader
    if h.observe(nil)!=replyPending || h.observe(alert[:1])!=replyPending ||
        h.observe(nil)!=replyPending || h.observe(alert[1:5])!=replyAlert {t.Fatal("empty fragment")}
}

func TestFragmentedAlertThroughTCPAdapter(t *testing.T) {
    outgoing,incoming:=tcpCopyPair(t)
    deadline:=time.Now().Add(3*time.Second)
    _=outgoing.SetDeadline(deadline)
    _=incoming.SetDeadline(deadline)
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplitFirst},diagnostic:true}
    defer conn.Close()
    before:=diagnosticStage.tcpFirstReply.Load()
    alerts:=diagnosticStage.tcpFirstTLSAlert.Load()
    alert:=[]byte{21,3,3,0,2,2,40}
    got:=make([]byte,len(alert))
    for i,b:=range alert {
        if _,err:=incoming.Write([]byte{b});err!=nil {t.Fatal(err)}
        if _,err:=io.ReadFull(conn,got[i:i+1]);err!=nil {t.Fatal(err)}
        if i<4 && diagnosticStage.tcpFirstTLSAlert.Load()!=alerts {t.Fatal("premature classification")}
    }
    if !bytes.Equal(got,alert) ||
        diagnosticStage.tcpFirstReply.Load()!=before+1 ||
        diagnosticStage.tcpFirstTLSAlert.Load()!=alerts+1 {t.Fatal("incorrect reply accounting")}
}

func TestFirstReplyDownstreamAdmission(t *testing.T) {
    for _,tc:=range []struct{data []byte;want bool}{
        {nil,false}, {[]byte{21},false},{[]byte{21,3,3,0,2},false},
        {[]byte{21,3,3,0,2,2,40},false},{[]byte("normal reply"),true},
        {[]byte{21,2,3,0,2},true},
    } {
        var h firstReplyHeader
        for _,b:=range tc.data {h.observe([]byte{b})}
        if h.admitsDownstream()!=tc.want {t.Fatal("unexpected learning admission",tc.data)}
        h.observe(nil)
        if h.admitsDownstream()!=tc.want {t.Fatal("empty read changed classification")}
    }
}

func TestTCPAlertEvidenceRemainsNeutralForSelector(t *testing.T) {
    for _,tc:=range []struct{
        name,method,preferred string
        data []byte
        diagnostic bool
        weak int
        wantPlain bool
    }{
        {"baseline-alert","pass","pass",[]byte{21,3,3,0,2,2,40},false,1,false},
        {"candidate-alert","split","split",[]byte{21,3,3,0,2,2,40},false,1,false},
        {"incomplete-alert","split","split",[]byte{21,3},false,1,false},
        {"large-alert-like-flow","split","",append([]byte{21,3,3,0,2,2,40},bytes.Repeat([]byte{1},adaptivePayloadThreshold)...),false,0,false},
        {"diagnostic-reply","pass","pass",[]byte("reply"),true,1,false},
        {"ordinary-baseline","pass","pass",[]byte("reply"),false,0,true},
    } {
        t.Run(tc.name,func(t *testing.T){
            const host="first-reply-learning.example.test"
            zapret2Auto.mu.Lock()
            old,exists:=zapret2Auto.entries[host]
            delete(zapret2Auto.entries,host)
            zapret2Auto.mu.Unlock()
            t.Cleanup(func(){
                zapret2Auto.mu.Lock()
                defer zapret2Auto.mu.Unlock()
                if exists {zapret2Auto.entries[host]=old} else {delete(zapret2Auto.entries,host)}
            })
            _=zapret2Auto.chooseSocketLive(host,localdpi.TLS)
            zapret2Auto.mu.Lock()
            entry:=zapret2Auto.entries[host]
            entry.preferred=tc.preferred
            entry.plainReachable=false
            entry.weakFailures=tc.weak
            generation:=zapret2Auto.generation
            zapret2Auto.mu.Unlock()
            pick:=boundTestSocketPick(host,tc.method,generation,localdpi.TLS)
            if pick.entryID==0 {t.Fatal("test selection not bound")}
            outgoing,incoming:=tcpCopyPair(t)
            deadline:=time.Now().Add(3*time.Second)
            _=outgoing.SetDeadline(deadline)
            _=incoming.SetDeadline(deadline)
            conn:=&desyncConn{TCPConn:outgoing,firstDone:true,diagnostic:tc.diagnostic}
            conn.adaptiveSelection.Store(pick)
            defer conn.Close()
            sent:=make(chan error,1)
            go func(){
                _,err:=incoming.Write(tc.data)
                sent<-err
            }()
            got:=make([]byte,len(tc.data))
            // Force the classification across separate reads regardless
            // of TCP packet coalescing on the host.
            if _,err:=io.ReadFull(conn,got[:1]);err!=nil {t.Fatal(err)}
            if _,err:=io.ReadFull(conn,got[1:]);err!=nil {t.Fatal(err)}
            if err:=<-sent;err!=nil {t.Fatal(err)}
            if !bytes.Equal(got,tc.data) || conn.received.Load()!=int64(len(got)) {
                t.Fatal("transport accounting or delivery changed")
            }
            if err:=conn.Close();err!=nil {t.Fatal(err)}
            zapret2Auto.mu.Lock()
            preferred,weak,plain:=entry.preferred,entry.weakFailures,entry.plainReachable
            zapret2Auto.mu.Unlock()
            if preferred!=tc.preferred || weak!=tc.weak || plain!=tc.wantPlain {
                t.Fatalf("unexpected learning: preferred=%q weak=%d plain=%t",preferred,weak,plain)
            }
        })
    }
}
