package localdpi

import (
    "bufio"
    "bytes"
    "io"
    "net/http"
    "testing"
)

func TestHTTPHostOWSTabPreservesRequest(t *testing.T) {
    for _,raw:=range []string{
        "GET /p HTTP/1.1\r\nHost: example.test\r\n\r\n",
        "POST / HTTP/1.1\r\nHOST: \t example.test:80 \t\r\nContent-Length: 4\r\n\r\nbody",
    } {
        first:=[]byte(raw)
        field,ok:=httpHostField(first)
        if !ok {t.Fatal("bad fixture")}
        out,ok:=HTTPHostOWSTab(first)
        start:=field.nameStart+5
        if !ok || len(out)!=len(first) || !bytes.Equal(out[:start],first[:start]) ||
            !bytes.Equal(out[field.valueStart:],first[field.valueStart:]) ||
            !bytes.Equal(out[start:field.valueStart],bytes.Repeat([]byte{'\t'},field.valueStart-start)) {
            t.Fatal("incorrect rewrite")
        }
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
            a.Proto!=b.Proto || !bytes.Equal(bodyA,bodyB) {t.Fatal("semantics changed")}
        out[0]^=1
        if string(first)!=raw {t.Fatal("input changed")}
    }
}

func TestHTTPHostOWSTabRejectsMissingOrAmbiguousWhitespace(t *testing.T) {
    for _,raw:=range []string{
        "", "GET / HTTP/1.1\r\nHost:example.test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: example.test",
        "GET / HTTP/1.1\r\nHost: a.test\r\nHost: b.test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost : a.test\r\n\r\n",
        "GET / HTTP/1.1\r\nHost: \r\n\r\n",
    } {
        if out,ok:=HTTPHostOWSTab([]byte(raw));ok || out!=nil {t.Fatal("ineligible request rewritten")}
    }
}
