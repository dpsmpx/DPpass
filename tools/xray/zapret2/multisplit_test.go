//go:build linux

package zapret2

import (
    "bytes"
    "encoding/json"
    "testing"
)

func TestMultiSplitPlanAndWire(t *testing.T) {
    first:=tlsClientHelloFixture(t,"example.test")
    original:=bytes.Clone(first)
    tag:=TagPrefix+"multisplit"
    p,err:=BuildPlan(tag,"tcp",first)
    if err!=nil || !p.Applied || p.Cut!=1 || p.Cut2<=p.Cut || p.Cut2>=len(first) {
        t.Fatal("invalid multi-split",p,err)
    }
    s,e,ok:=SNIRange(first)
    if !ok || p.Cut2!=s+(e-s)/2 || !bytes.Equal(original,first) {t.Fatal("unexpected split")}
    encoded,err:=json.Marshal(Response{Plan:p})
    if err!=nil {t.Fatal(err)}
    var decoded Response
    if err:=decodePlannerJSON(encoded,&decoded);err!=nil {t.Fatal(err)}
    if err:=validatePlan(tag,"tcp",first,decoded.Plan);err!=nil {t.Fatal(err)}
    for _,bad:=range []int{-1,0,1,p.Cut2+1,len(first)} {
        q:=p
        q.Cut2=bad
        if validatePlan(tag,"tcp",first,q)==nil {t.Fatal("accepted foreign cut",bad)}
    }
    other,err:=BuildPlan(TagPrefix+"split","tcp",first)
    if err!=nil {t.Fatal(err)}
    other.Cut2=p.Cut2
    if validatePlan(other.Strategy,"tcp",first,other)==nil {t.Fatal("second cut accepted outside multi-split")}
}

func TestMultiSplitDeclinesIncompleteAndOtherProtocols(t *testing.T) {
    first:=tlsClientHelloFixture(t,"example.test")
    for _,input:=range [][]byte{first[:9],first[:len(first)-1],[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),tlsClientHelloFixture(t,"127.0.0.1")} {
        p,err:=BuildPlan(TagPrefix+"multisplit","tcp",input)
        if err!=nil || p.Applied || p.Cut!=0 || p.Cut2!=0 {t.Fatal("ineligible input",p,err)}
    }
    p,err:=BuildPlan(TagPrefix+"multisplit","udp",make([]byte,1200))
    if err!=nil || p.Applied || p.Cut2!=0 {t.Fatal("UDP multi-split",p,err)}
}
