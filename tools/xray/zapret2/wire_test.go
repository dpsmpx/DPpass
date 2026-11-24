//go:build linux

package zapret2

import (
    "bytes"
    "encoding/json"
    "strings"
    "testing"
)

func TestReadRequestBoundedAndStrict(t *testing.T) {
    var b bytes.Buffer
    want:=Request{Tag:TagPrefix+"pass",Network:"tcp",First:make([]byte,MaxFirst)}
    if err:=json.NewEncoder(&b).Encode(want);err!=nil {t.Fatal(err)}
    req,err:=ReadRequest(&b)
    if err!=nil || req.Tag!=want.Tag || req.Network!=want.Network || !bytes.Equal(req.First,want.First) {
        t.Fatal("maximum legal request rejected",err)
    }
    for _,raw:=range []string{
        "null\n","{}\n",
        "{\"tag\":\"dppass:exp-pass\",\"network\":\"tcp\",\"extra\":1}\n",
        "{\"tag\":\"dppass:exp-pass\",\"network\":\"tcp\"} {}\n",
        "{\"tag\":\"dppass:exp-auto\",\"network\":\"tcp\"}\n",
        "{\"tag\":\"dppass:exp-pass\",\"network\":\"invalid\"}\n",
        "{\"tag\":\"dppass:exp-pass\",\"network\":\"tcp\"}",
        strings.Repeat(" ",MaxRequestFrame)+"\n",
    } {
        if _,err:=ReadRequest(strings.NewReader(raw));err==nil {t.Fatal("malformed request accepted")}
    }
    b.Reset()
    want.First=make([]byte,MaxFirst+1)
    if err:=json.NewEncoder(&b).Encode(want);err!=nil {t.Fatal(err)}
    if _,err:=ReadRequest(&b);err==nil {t.Fatal("oversize decoded request accepted")}
}

func TestReadRequestDoesNotReadUnboundedStream(t *testing.T) {
    reader:=strings.NewReader(strings.Repeat("x",MaxRequestFrame*4))
    before:=reader.Len()
    if _,err:=ReadRequest(reader);err==nil {t.Fatal("unterminated oversized frame accepted")}
    if before-reader.Len()>MaxRequestFrame+1 {t.Fatal("read past frame allocation limit")}
}
