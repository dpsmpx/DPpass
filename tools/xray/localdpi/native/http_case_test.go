//go:build linux && cgo && localdpi_native

package native

import (
    "bytes"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func TestNativeHTTPCaseFixture(t *testing.T) {
    first:=[]byte(httpCaseFixture)
    before:=bytes.Clone(first)
    expected,ok:=localdpi.HTTPHostNameCase(first)
    if !ok {t.Fatal("invalid reference fixture")}
    got,ok:=HTTPHostCaseFixture(first)
    if !ok || !bytes.Equal(got,expected) || !bytes.Equal(first,before) {
        t.Fatal("native/reference mismatch")
    }
    got[0]^=1
    if !bytes.Equal(first,before) {t.Fatal("output aliases input")}
    for i:=range first {
        mutated:=bytes.Clone(first)
        mutated[i]^=1
        if out,ok:=HTTPHostCaseFixture(mutated);ok || out!=nil {
            t.Fatal("non-fixture passed to native HTTP",i)
        }
        if out,ok:=HTTPHostCaseFixture(first[:i]);ok || out!=nil {
            t.Fatal("truncated fixture accepted",i)
        }
    }
}
