//go:build !linux || !cgo || !localdpi_native

package native

import "testing"

func TestDefaultInspectionUnavailable(t *testing.T) {
    if hint,ok:=Inspect([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"));ok || hint!=Unknown {
        t.Fatal("default build claimed native capability")
    }
}

func TestDefaultTLSNameAgreementUnavailable(t *testing.T) {
    if TLSNameAgrees([]byte{22,3,3,0,4,1,0,0,0}) {t.Fatal("native parser unavailable")}
}

func TestDefaultTLSRecordChainUnavailable(t *testing.T) {
    if out,ok:=SplitTLSRecordChain(make([]byte,64),10,20);ok || out!=nil {t.Fatal("native chain unavailable")}
}
