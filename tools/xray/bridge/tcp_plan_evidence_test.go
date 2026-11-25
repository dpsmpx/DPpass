//go:build linux

package bridge

import (
    "testing"
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
