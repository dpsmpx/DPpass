//go:build linux

package zapret2

import (
    "bytes"
    "testing"
)

func TestCombinedHTTPHostPlan(t *testing.T) {
    first:=LocalHTTPFixture()
    tag:=TagPrefix+"http-host-combined"
    p,err:=BuildPlan(tag,"tcp",first)
    expected:=bytes.Replace(first,[]byte("\r\nHost: "),[]byte("\r\nhOsT:\t"),1)
    if err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,expected) {t.Fatal("combined operation",err)}
    if err:=validatePlan(tag,"tcp",first,p);err!=nil {t.Fatal(err)}
    p.Rewrite=bytes.Clone(p.Rewrite)
    p.Rewrite[len(p.Rewrite)-1]^=1
    if validatePlan(tag,"tcp",first,p)==nil {t.Fatal("modified body admitted")}
    for _,input:=range [][]byte{[]byte("GET / HTTP/1.1\r\nHost:example.test\r\n\r\n"),[]byte("GET / HTTP/1.1\r\nHost: incomplete")} {
        plan,err:=BuildPlan(tag,"tcp",input)
        if err!=nil || plan.Applied || len(plan.Rewrite)!=0 {t.Fatal("partial operation admitted",err)}
    }
}
