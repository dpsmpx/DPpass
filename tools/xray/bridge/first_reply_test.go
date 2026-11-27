//go:build linux

package bridge

import (
    "bytes"
    "io"
    "testing"
    "time"
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
