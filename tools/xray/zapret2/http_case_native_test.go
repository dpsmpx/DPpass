//go:build linux && cgo && localdpi_native

package zapret2

import (
    "bytes"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/localdpi/native"
)

func TestTaggedHTTPPlannerNativeAndPortableParity(t *testing.T) {
    prev:=PlannerSocket()
    if err:=SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = SetPlannerSocket(prev)})
    for _,tc:=range []struct{host string;nativeOK bool}{
        {"example.com",true},{"other.test",true},{"local.test:80",false},{"[::1]",false},
    } {
        first:=[]byte("GET / HTTP/1.1\r\nHost: "+tc.host+"\r\n\r\n")
        expected,ok:=localdpi.HTTPHostNameCase(first)
        if !ok {t.Fatal("bad reference")}
        b,ok:=native.HTTPHostCase(first)
        if ok!=tc.nativeOK || ok && !bytes.Equal(b,expected) {t.Fatal("native admission",tc.host)}
        p,err:=PlanForDiagnostic(TagPrefix+"http-hostcase","tcp",first)
        if err!=nil || !p.Applied || !bytes.Equal(p.Rewrite,expected) {t.Fatal("plan parity",err)}
    }
}
