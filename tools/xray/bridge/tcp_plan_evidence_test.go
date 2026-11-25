//go:build linux

package bridge

import (
    "testing"
    "bytes"
    "io"
    "net"
    "time"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestTCPPlanEvidenceMatchesExecutedMethod(t *testing.T) {
    for _,tc:=range []struct{
        host,method string
        transport localdpi.Transport
        applied bool
        cut int
        want bool
    }{
        {"example.test","pass",localdpi.TLS,false,0,true},
        {"http:example.test","pass",localdpi.HTTP,false,0,true},
        {"http:example.test","split-1",localdpi.HTTP,false,0,false},
        {"http:example.test","split",localdpi.HTTP,false,0,false},
        {"example.test","split-1",localdpi.TLS,true,1,true},
        {"example.test","tlsrec-split",localdpi.TLS,false,0,false},
        {"example.test","tlsrec-split",localdpi.TLS,true,40,true},
        {"example.test","fake-5",localdpi.TLS,true,1,false},
        {"example.test","disorder",localdpi.TLS,true,1,false},
        {"example.test","split",localdpi.TLS,true,1,false},
        {"http:example.test","split",localdpi.HTTP,true,20,true},
        {"udp:example.test","pass",localdpi.QUIC,false,0,false},
    }{
        pick:=newSocketPick(tc.host,tc.method,1,tc.transport)
        p:=zapret2.Plan{Strategy:zapret2.TagPrefix+tc.method,Network:"tcp",Applied:tc.applied,Cut:tc.cut}
        if got:=tcpPlanMatchesSelection(pick,p);got!=tc.want {t.Fatalf("%+v got %v",tc,got)}
        p.Strategy=zapret2.TagPrefix+"different"
        if tcpPlanMatchesSelection(pick,p) {t.Fatal("mismatched plan admitted")}
    }
    if tcpPlanMatchesSelection(nil,zapret2.Plan{}) {t.Fatal("missing selection admitted")}
}

func TestTCPPublishesEvidenceOnlyAfterMatchingWrite(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    for _,tc:=range []struct{method, executed string; want bool; closeBeforeWrite bool}{
        {"pass","pass",true,false},
        {"split","split",true,false},
        {"split-1","pass",true,false},
        {"pass","pass",false,true},
    } {
        out,peer:=tcpCopyPair(t)
        if err:=out.SetDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
        if err:=peer.SetDeadline(time.Now().Add(time.Second));err!=nil {t.Fatal(err)}
        host:="http:evidence-local.example.test|"+out.RemoteAddr().(*net.TCPAddr).IP.String()
        key:=canonicalAdaptiveKey(host)
        zapret2Auto.mu.Lock()
        old,exists:=zapret2Auto.entries[key]
        zapret2Auto.entries[key]=&adaptiveEntry{preferred:tc.method}
        zapret2Auto.mu.Unlock()
        func(){
            defer func(){
                zapret2Auto.mu.Lock()
                defer zapret2Auto.mu.Unlock()
                if exists {zapret2Auto.entries[key]=old} else {delete(zapret2Auto.entries,key)}
            }()
            conn:=&desyncConn{TCPConn:out,mode:desyncMode{kind:desyncAuto}}
            first:=[]byte("GET / HTTP/1.1\r\nHost: evidence-local.example.test\r\n\r\n")
            if tc.closeBeforeWrite {
                if err:=out.Close();err!=nil {t.Fatal(err)}
            }
            n,err:=conn.Write(first)
            if tc.closeBeforeWrite {
                if err==nil {t.Fatal("closed socket reported successful write")}
            } else {
                if err!=nil || n!=len(first) {t.Fatal("unexpected write result",n,err)}
                received:=make([]byte,len(first))
                if _,err:=io.ReadFull(peer,received);err!=nil || !bytes.Equal(first,received) {t.Fatal("wire bytes changed",err)}
            }
            pick:=conn.adaptiveSelection.Load()
            if (pick!=nil)!=tc.want || pick!=nil && pick.flow.MethodID!=tc.executed {
                t.Fatal("incorrect completed-method evidence",tc.method,tc.closeBeforeWrite,pick)
            }
        }()
    }
}

func TestHTTPUnavailableLegacyMethodIsNotAdvertised(t *testing.T) {
    first:=[]byte("GET / HTTP/1.1\r\nHost: evidence-local.example.test\r\n\r\n")
    p,err:=zapret2.BuildPlan(zapret2.TagPrefix+"split-1","tcp",first)
    if err!=nil || p.Applied {t.Fatal("legacy HTTP split-1 planner contract changed",err)}
    if socketCapabilities.Allows(localdpi.HTTP,"split-1") || !socketCapabilities.Allows(localdpi.TLS,"split-1") {
        t.Fatal("runtime capabilities do not match planner")
    }
    if localdpi.NeuralIndex("split-1",localdpi.HTTP)!=0 || localdpi.NeuralIndex("split-1",localdpi.TLS)!=0 {
        t.Fatal("historical model ABI changed")
    }
    if socketEvidenceAdmissible(newSocketPick("http:example.test","split-1",1,localdpi.HTTP),localdpi.SocketDownstream(4096)) {
        t.Fatal("unsupported HTTP evidence admitted")
    }
}
