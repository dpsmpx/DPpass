//go:build linux && cgo && localdpi_native

package native

import (
    "bytes"
    "strings"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func TestNativeHTTPCaseValidatedRequests(t *testing.T) {
    for _,raw:=range []string{
        "POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody",
        "GET /?q=1 HTTP/1.1\r\nX-Foo: hi\r\nhOST:\t other.test \t\r\n\r\n",
        "HEAD / HTTP/1.0\r\nHOST: local.test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: "+strings.Repeat("a",253)+"\r\n\r\n",
    } {
        first:=[]byte(raw)
        before:=bytes.Clone(first)
        expected,ok:=localdpi.HTTPHostNameCase(first)
        if !ok {t.Fatal("invalid reference fixture")}
        got,ok:=HTTPHostCase(first)
        if !ok || !bytes.Equal(got,expected) || !bytes.Equal(first,before) {
            t.Fatal("native/reference mismatch")
        }
        got[0]^=1
        if !bytes.Equal(first,before) {t.Fatal("output aliases input")}
    }
}
func TestNativeHTTPCaseRejectsUnsafeAuthorities(t *testing.T) {
    for _,host:=range []string{"","a","123","a1","1a","example.test:80","[::1]","a b","a\x00b",strings.Repeat("a",254)} {
        first:=[]byte("GET / HTTP/1.1\r\nHost: "+host+"\r\n\r\n")
        if out,ok:=HTTPHostCase(first);ok || out!=nil {t.Fatal("unsupported authority accepted",host)}
    }
    for _,raw:=range []string{
        "GET / HTTP/1.1\r\nHost: example.test",
        "GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
        "GET / HTTP/1.1\r\nX: x\r\n\r\nHost: example.test",
    } {
        if out,ok:=HTTPHostCase([]byte(raw));ok || out!=nil {t.Fatal("malformed request accepted")}
    }
}
