//go:build linux && localdpi_native && cgo

package zapret2

import (
    "bytes"
    "path/filepath"
    "testing"
)

func TestTaggedLocalHTTPFixtureDispatch(t *testing.T) {
    prev:=PlannerSocket()
    if err:=SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = SetPlannerSocket(prev)})
    tag:=TagPrefix+"http-hostcase"
    first:=LocalHTTPFixture()
    if !localNativeHTTPDiagnostic(tag,"tcp",first,true) {t.Fatal("native fixture not admitted")}
    for _,tc:=range []struct{tag,network string;first []byte;diagnostic bool}{
        {tag,"tcp",first,false},
        {tag,"udp",first,true},
        {TagPrefix+"http-hostows","tcp",first,true},
        {tag,"tcp",first[:len(first)-1],true},
        {tag,"tcp",append(bytes.Clone(first),0),true},
        {tag,"tcp",[]byte("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"),true},
    } {
        if localNativeHTTPDiagnostic(tc.tag,tc.network,tc.first,tc.diagnostic) {t.Fatal("unintended local dispatch")}
    }
    p,err:=PlanForDiagnostic(tag,"tcp",first)
    expected:=bytes.Replace(first,[]byte("\r\nHost:"),[]byte("\r\nhOsT:"),1)
    if err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,expected) {t.Fatal("native fixture plan",err)}
    if _,err:=PlanFor(tag,"tcp",first);err==nil {t.Fatal("ordinary planning bypassed selected daemon")}
    if _,err:=PlanForDiagnostic(tag,"tcp",[]byte("GET / HTTP/1.1\r\nHost: other.test\r\n\r\n"));err==nil {
        t.Fatal("non-fixture bypassed selected daemon")
    }
    if _,err:=PlanForDiagnostic(TagPrefix+"http-hostows","tcp",first);err==nil {t.Fatal("OWS bypassed selected daemon")}
}
