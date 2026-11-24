//go:build linux

package zapret2

import (
    "bytes"
    "encoding/json"
    "net"
    "path/filepath"
    "testing"
    "time"
)

func TestPlanValidationPreservesExistingLocalOutputs(t *testing.T) {
    for _,first:=range [][]byte{
        tlsClientHelloFixture(t,"example.test"),
        {22,3,3,0,4,1,0,0,0},
        []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
        []byte("unrecognized"),
    } {
        for _,method:=range []string{"pass","split-1","split-2","split","disorder","fake-3","fake-5","tlsrec-split"} {
            tag:=TagPrefix+method
            p,err:=BuildPlan(tag,"tcp",first)
            if err!=nil {t.Fatal(err)}
            if err:=validatePlan(tag,"tcp",first,p);err!=nil {t.Fatal(method,err)}
        }
    }
    initial:=make([]byte,1200)
    initial[0],initial[4]=0xc0,1
    for _,method:=range []string{"pass","fake-3","fake-5","split"} {
        tag:=TagPrefix+method
        p,err:=BuildPlan(tag,"udp",initial)
        if err!=nil {t.Fatal(err)}
        if err:=validatePlan(tag,"udp",initial,p);err!=nil {t.Fatal(method,err)}
    }
}

func TestPlanValidationRejectsCorruptedTLSRecord(t *testing.T) {
    first:=append(tlsClientHelloFixture(t,"example.test"),23,3,3,0,1,0x55)
    tag:=TagPrefix+"tlsrec-split"
    good,err:=BuildPlan(tag,"tcp",first)
    if err!=nil || !good.Applied {t.Fatal(err)}
    for _,change:=range []func(*Plan){
        func(p *Plan){p.Rewrite[0]^=1},
        func(p *Plan){p.Rewrite[4]^=1},
        func(p *Plan){p.Rewrite[9]^=1},
        func(p *Plan){p.Rewrite[p.Cut]^=1},
        func(p *Plan){p.Rewrite[p.Cut+4]^=1},
        func(p *Plan){p.Rewrite[p.Cut+5]^=1},
        func(p *Plan){p.Rewrite[len(p.Rewrite)-1]^=1},
        func(p *Plan){p.Cut++},
        func(p *Plan){p.Repeats=1},
        func(p *Plan){p.TTL=1},
        func(p *Plan){p.Applied=false},
    } {
        p:=good
        p.Rewrite=bytes.Clone(good.Rewrite)
        change(&p)
        if validatePlan(tag,"tcp",first,p)==nil {t.Fatal("corrupt plan accepted")}
    }
}

func TestIPCRejectsAppliedBaselineWithoutFallback(t *testing.T) {
    prev:=PlannerSocket()
    path:=filepath.Join(t.TempDir(),"planner.sock")
    ln,err:=net.Listen("unix",path)
    if err!=nil {t.Fatal(err)}
    t.Cleanup(func(){ln.Close();_ = SetPlannerSocket(prev)})
    if err:=SetPlannerSocket(path);err!=nil {t.Fatal(err)}
    result:=make(chan error,1)
    go func(){
        conn,err:=ln.Accept()
        if err!=nil {result<-err;return}
        defer conn.Close()
        _ = conn.SetDeadline(time.Now().Add(2*time.Second))
        var req Request
        if err:=json.NewDecoder(conn).Decode(&req);err!=nil {result<-err;return}
        result<-json.NewEncoder(conn).Encode(Response{Plan:Plan{
            Strategy:req.Tag,Network:req.Network,Applied:true,Cut:1,
        }})
    }()
    first:=[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    if p,err:=PlanFor(TagPrefix+"pass","tcp",first);err==nil || p.Applied {
        t.Fatal("invalid IPC result accepted")
    }
    if err:=<-result;err!=nil {t.Fatal(err)}
}

func TestLocalDispatchChecksPlanContract(t *testing.T) {
    prev:=PlannerSocket()
    t.Cleanup(func(){_ = SetPlannerSocket(prev)})
    if err:=SetPlannerSocket("");err!=nil {t.Fatal(err)}
    first:=tlsClientHelloFixture(t,"example.test")
    if p,err:=PlanFor(TagPrefix+"tlsrec-split","tcp",first);err!=nil || !p.Applied {
        t.Fatal("valid local output rejected",err)
    }
    if _,err:=PlanFor("not-a-local-method","tcp",first);err==nil {
        t.Fatal("unrecognized local strategy accepted")
    }
    if _,err:=PlanFor(TagPrefix+"pass","invalid",first);err==nil {
        t.Fatal("unrecognized transport accepted")
    }
}
