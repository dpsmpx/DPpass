package localdpi

import (
    "bufio"
    "bytes"
    "io"
    "net/http"
    "testing"
)

func TestHTTPHostNameCasePreservesRequest(t *testing.T) {
    for _,raw:=range []string{
        "GET /path?q=1 HTTP/1.1\r\nHost: example.test\r\nX-Example: Host: value\r\n\r\n",
        "POST / HTTP/1.1\r\nHOST: [::1]:8080\r\nContent-Length: 16\r\n\r\nHost: body.test!",
        "GET / HTTP/1.0\r\nhost:\t example.test:80 \t\r\n\r\n",
    } {
        first:=[]byte(raw)
        before:=bytes.Clone(first)
        out,ok:=HTTPHostNameCase(first)
        if !ok || !PreservesHTTPHostNameCase(first,out) {t.Fatal("valid request rejected")}
        field,_:=httpHostField(first)
        if string(out[field.nameStart:field.nameStart+4])!="hOSt" {t.Fatal("wrong field spelling")}
        a,err:=http.ReadRequest(bufio.NewReader(bytes.NewReader(first)))
        if err!=nil {t.Fatal(err)}
        b,err:=http.ReadRequest(bufio.NewReader(bytes.NewReader(out)))
        if err!=nil {t.Fatal(err)}
        bodyA,err:=io.ReadAll(a.Body)
        if err!=nil {t.Fatal(err)}
        bodyB,err:=io.ReadAll(b.Body)
        if err!=nil {t.Fatal(err)}
        a.Body.Close()
        b.Body.Close()
        if a.Host!=b.Host || a.Method!=b.Method || a.RequestURI!=b.RequestURI ||
            a.Proto!=b.Proto || !bytes.Equal(bodyA,bodyB) {t.Fatal("request semantics changed")}
        if !bytes.Equal(first,before) {t.Fatal("input mutated")}
        out[len(out)-1]^=1
        if !bytes.Equal(first,before) {t.Fatal("output aliases input")}
        if PreservesHTTPHostNameCase(first,out) {t.Fatal("unrelated mutation accepted")}
    }
}

func TestHTTPHostNameCaseRejectsAmbiguousRequests(t *testing.T) {
    for _,first:=range [][]byte{
        nil,
        []byte("GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n"),
        []byte("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
        []byte("GET / HTTP/1.1\r\nHost: a.test"),
        []byte("GET / HTTP/1.1\r\nX: a\r\n\r\nHost: body.test"),
        make([]byte,16385),
    } {
        before:=bytes.Clone(first)
        if out,ok:=HTTPHostNameCase(first);ok || out!=nil {t.Fatal("ambiguous request accepted")}
        if !bytes.Equal(first,before) {t.Fatal("input mutated")}
    }
}
