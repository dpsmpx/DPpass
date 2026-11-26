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

func TestReadResponseBoundedAndStrict(t *testing.T) {
    var b bytes.Buffer
    want:=Response{Plan:Plan{Strategy:TagPrefix+"tlsrec-split",Network:"tcp",
        Applied:true,Cut:10,Rewrite:make([]byte,MaxFirst+5)}}
    if err:=json.NewEncoder(&b).Encode(want);err!=nil {t.Fatal(err)}
    got,err:=readResponse(&b)
    if err!=nil || !bytes.Equal(got.Plan.Rewrite,want.Plan.Rewrite) {t.Fatal("legal response rejected",err)}
    for _,raw:=range []string{
        "null\n","{}\n",
        "{\"plan\":{\"strategy\":\"dppass:exp-pass\",\"network\":\"tcp\"},\"extra\":1}\n",
        "{\"plan\":{\"strategy\":\"dppass:exp-pass\",\"network\":\"tcp\",\"unknown\":true}}\n",
        "{\"plan\":{\"strategy\":\"dppass:exp-pass\",\"network\":\"tcp\"}} {}\n",
        "{\"plan\":{\"strategy\":\"dppass:exp-pass\",\"network\":\"tcp\"},\"error\":\"failed\"}\n",
        "{\"plan\":{\"strategy\":\"dppass:exp-pass\",\"network\":\"tcp\"}}",
        strings.Repeat(" ",MaxResponseFrame)+"\n",
    } {
        if _,err:=readResponse(strings.NewReader(raw));err==nil {t.Fatal("malformed response accepted")}
    }
    b.Reset()
    if err:=json.NewEncoder(&b).Encode(Response{Error:"planner unavailable"});err!=nil {t.Fatal(err)}
    if got,err:=readResponse(&b);err!=nil || got.Error!="planner unavailable" {t.Fatal("error response rejected",err)}
    reader:=strings.NewReader(strings.Repeat("x",MaxResponseFrame*4))
    before:=reader.Len()
    if _,err:=readResponse(reader);err==nil {t.Fatal("oversize response accepted")}
    if before-reader.Len()>MaxResponseFrame+1 {t.Fatal("unbounded read")}
}

func TestPlannerWireRejectsAmbiguousFieldRepresentations(t *testing.T) {
    for _,raw:=range []string{
        `{"tag":"dppass:exp-pass","tag":"dppass:exp-split","network":"tcp"}`,
        `{"tag":"dppass:exp-pass","network":"tcp","Network":"udp"}`,
        `{"Tag":"dppass:exp-pass","network":"tcp"}`,
        `{"tag":"dppass:exp-pass","network":"tcp","first":[1,2,3]}`,
        `{"tag":"dppass:exp-pass","network":"tcp","first":{"nested":true}}`,
        `[]`,
    } {
        if _,err:=ReadRequest(strings.NewReader(raw+"\n"));err==nil {t.Fatal("ambiguous request accepted",raw)}
        if _,err:=ReadStandaloneRequest(strings.NewReader(raw));err==nil {t.Fatal("ambiguous CLI request accepted",raw)}
    }
    for _,raw:=range []string{
        `{"plan":{"strategy":"dppass:exp-pass","network":"tcp","applied":false,"applied":true}}`,
        `{"plan":{"strategy":"dppass:exp-pass","network":"tcp","Cut":1}}`,
        `{"plan":{"strategy":"dppass:exp-pass","network":"tcp","fake":[0]}}`,
        `{"plan":{"strategy":"dppass:exp-pass","network":"tcp"},"plan":{"strategy":"dppass:exp-split","network":"tcp"}}`,
        `{"plan":null}`,
        `{"Error":"failed"}`,
    } {
        if _,err:=readResponse(strings.NewReader(raw+"\n"));err==nil {t.Fatal("ambiguous response accepted",raw)}
    }
}

func TestStandalonePlannerRequestBoundedAndSingleObject(t *testing.T) {
    valid:=`{"tag":"dppass:exp-pass","network":"tcp","first":"AQID"}`
    for _,raw:=range []string{valid,valid+"\n","  "+valid+"\n  "} {
        got,err:=ReadStandaloneRequest(strings.NewReader(raw))
        if err!=nil || got.Tag!=TagPrefix+"pass" || !bytes.Equal(got.First,[]byte{1,2,3}) {
            t.Fatal("valid standalone request rejected",err)
        }
    }
    for _,raw:=range []string{valid+" "+valid,valid+" garbage",`{"tag":"dppass:exp-auto","network":"tcp"}`,
        strings.Repeat(" ",MaxRequestFrame)+valid} {
        if _,err:=ReadStandaloneRequest(strings.NewReader(raw));err==nil {t.Fatal("invalid standalone request accepted")}
    }
    stream:=strings.NewReader(strings.Repeat(" ",MaxRequestFrame*4))
    before:=stream.Len()
    if _,err:=ReadStandaloneRequest(stream);err==nil || before-stream.Len()>MaxRequestFrame+1 {
        t.Fatal("standalone reader did not enforce input bound")
    }
}
