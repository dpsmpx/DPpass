//go:build linux && cgo && localdpi_native

package zapret2

import (
    "bytes"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/localdpi/native"
)

func TestTaggedHTTPFixturePlannerParity(t *testing.T) {
    prev:=PlannerSocket()
    if err:=SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = SetPlannerSocket(prev)})
    first:=[]byte("POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody")
    expected,ok:=native.HTTPHostCaseFixture(first)
    if !ok {t.Fatal("native fixture unavailable")}
    p,err:=PlanForDiagnostic(TagPrefix+"http-hostcase","tcp",first)
    if err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,expected) {t.Fatal("native parity",err)}
    other:=[]byte("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n")
    if _,ok:=native.HTTPHostCaseFixture(other);ok {t.Fatal("arbitrary native input")}
    want,ok:=localdpi.HTTPHostNameCase(other)
    p,err=PlanForDiagnostic(TagPrefix+"http-hostcase","tcp",other)
    if !ok || err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,want) {t.Fatal("portable parity",err)}
}
