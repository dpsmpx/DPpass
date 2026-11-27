//go:build linux

package zapret2

import (
    "bytes"
    "testing"
)

func TestHTTPHostCasePlannerExactRewrite(t *testing.T) {
    first:=[]byte("POST /path HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody")
    expected:=[]byte("POST /path HTTP/1.1\r\nhOSt: example.test\r\nContent-Length: 4\r\n\r\nbody")
    tag:=TagPrefix+"http-hostcase"
    p,err:=BuildPlan(tag,"tcp",first)
    if err!=nil || !p.Applied || p.Cut!=0 || !bytes.Equal(p.Rewrite,expected) {t.Fatalf("bad HTTP plan: %+v %v",p,err)}
    if err:=validatePlan(tag,"tcp",first,p);err!=nil {t.Fatal(err)}
    for _,change:=range []func(*Plan){
        func(p *Plan){p.Rewrite=bytes.Clone(first)},
        func(p *Plan){p.Rewrite[len(p.Rewrite)-1]^=1},
        func(p *Plan){p.Cut=1},
        func(p *Plan){p.Fake=[]byte{1}},
        func(p *Plan){p.Applied=false},
    } {
        bad:=p
        bad.Rewrite=bytes.Clone(p.Rewrite)
        change(&bad)
        if validatePlan(tag,"tcp",first,bad)==nil {t.Fatal("corrupt HTTP plan accepted")}
    }
    if !bytes.Equal(first,[]byte("POST /path HTTP/1.1\r\nHost: example.test\r\nContent-Length: 4\r\n\r\nbody")) {t.Fatal("input modified")}
}

func TestHTTPHostCaseDoesNotRewriteOtherProtocols(t *testing.T) {
    for _,first:=range [][]byte{
        []byte("GET / HTTP/1.1\r\nHost: incomplete"),
        []byte("GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"),
        tlsClientHelloFixture(t,"example.test"),
        []byte("SSH-2.0-example\r\n"),
    } {
        p,err:=BuildPlan(TagPrefix+"http-hostcase","tcp",first)
        if err!=nil || p.Applied || len(p.Rewrite)!=0 {t.Fatal("non-eligible input rewritten",err)}
    }
    p,err:=BuildPlan(TagPrefix+"http-hostcase","udp",make([]byte,1200))
    if err!=nil || p.Applied || len(p.Rewrite)!=0 {t.Fatal("UDP rewritten",err)}
}
