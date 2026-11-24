package localdpi

import (
    "bytes"
    "testing"
)

func TestHTTPHostFieldOffsets(t *testing.T) {
    raw:=[]byte("POST / HTTP/1.1\r\nX-Other: Host: fake.test\r\nhOsT:\t [::1]:8080 \t\r\nContent-Length: 16\r\n\r\nHost: body.test")
    before:=bytes.Clone(raw)
    field,ok:=httpHostField(raw)
    if !ok || string(raw[field.nameStart:field.nameStart+4])!="hOsT" ||
        string(raw[field.valueStart:field.valueEnd])!="[::1]:8080" {
        t.Fatal("incorrect header offsets")
    }
    s,e,ok:=HTTPHostRange(raw)
    if !ok || s!=field.valueStart || e!=field.valueEnd {t.Fatal("inconsistent parser output")}
    if !bytes.Equal(before,raw) {t.Fatal("mutated input")}
    for _,b:=range [][]byte{
        []byte("GET / HTTP/1.1\r\nHost: a.test\r\nhost: b.test\r\n\r\n"),
        []byte("GET / HTTP/1.1\r\nX: host\r\n\r\nHost: body.test"),
        []byte("GET / HTTP/1.1\r\nHost: a.test"),
    } {
        if field,ok:=httpHostField(b);ok || field!=(hostField{}) {t.Fatal("ambiguous field accepted")}
    }
}
