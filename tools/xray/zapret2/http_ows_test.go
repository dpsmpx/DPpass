//go:build linux

package zapret2

import (
    "bytes"
    "testing"
)

func TestHTTPHostOWSPlanAndIntegrity(t *testing.T) {
    first:=[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    tag:=TagPrefix+"http-hostows"
    p,err:=BuildPlan(tag,"tcp",first)
    if err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,[]byte("GET / HTTP/1.1\r\nHost:\texample.test\r\n\r\n")) {
        t.Fatal("incorrect plan",err)
    }
    if err:=validatePlan(tag,"tcp",first,p);err!=nil {t.Fatal(err)}
    for _,change:=range []func(*Plan){
        func(p *Plan){p.Rewrite=bytes.Clone(first)},
        func(p *Plan){p.Rewrite[len(p.Rewrite)-1]^=1},
        func(p *Plan){p.Applied=false},
        func(p *Plan){p.Cut=1},
        func(p *Plan){p.Cut2=2},
        func(p *Plan){p.Fake=[]byte{1}},
        func(p *Plan){p.Repeats=1},
    } {
        bad:=p
        bad.Rewrite=bytes.Clone(p.Rewrite)
        change(&bad)
        if validatePlan(tag,"tcp",first,bad)==nil {t.Fatal("invalid plan accepted")}
    }
    for _,tc:=range []struct{network string;data []byte}{
        {"tcp",[]byte("GET / HTTP/1.1\r\nHost:example.test\r\n\r\n")},
        {"tcp",tlsClientHelloFixture(t,"example.test")},
        {"udp",first},
    } {
        p,err:=BuildPlan(tag,tc.network,tc.data)
        if err!=nil || p.Applied || len(p.Rewrite)!=0 {t.Fatal("ineligible plan applied",err)}
        if err:=validatePlan(tag,tc.network,tc.data,p);err!=nil {t.Fatal(err)}
    }
}
