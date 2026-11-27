//go:build linux

package bridge

import (
    "bufio"
    "bytes"
    "io"
    "net/http"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestHTTPHostCaseOverRealTCPWithFragmentedHeader(t *testing.T) {
    previous:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(previous)})
    outgoing,incoming:=tcpCopyPair(t)
    request:=&diagnosticRequestCounters{}
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncHTTPHostCase},diagnostic:true,request:request}
    defer conn.Close()
    before,_:=DesyncStats()
    parts:=[]string{"PO","ST /path HTTP/1.1\r\nHo","st: example.test\r\nContent-Length: 4\r\n","\r\nbody"}
    for _,part:=range parts {
        if n,err:=conn.Write([]byte(part));err!=nil || n!=len(part) {t.Fatal("write",n,err)}
    }
    _ = incoming.SetReadDeadline(time.Now().Add(3*time.Second))
    expected:=[]byte("POST /path HTTP/1.1\r\nhOsT: example.test\r\nContent-Length: 4\r\n\r\nbody")
    raw:=make([]byte,len(expected))
    if _,err:=io.ReadFull(incoming,raw);err!=nil {t.Fatal(err)}
    if !bytes.Equal(raw,expected) {t.Fatal("incorrect wire request")}
    parsed,err:=http.ReadRequest(bufio.NewReader(bytes.NewReader(raw)))
    if err!=nil {t.Fatal(err)}
    body,err:=io.ReadAll(parsed.Body)
    parsed.Body.Close()
    if err!=nil || parsed.Host!="example.test" || parsed.Method!="POST" || string(body)!="body" {t.Fatal("HTTP semantics changed",err)}
    applied,skipped:=request.finish()
    if applied!=1 || skipped!=0 {t.Fatal("incorrect request accounting",applied,skipped)}
    after,_:=DesyncStats()
    if after!=before {t.Fatal("diagnostic polluted live counters")}
}

func TestExistingSplitHandlesFragmentedHTTP(t *testing.T) {
    outgoing,incoming:=tcpCopyPair(t)
    conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplit}}
    defer conn.Close()
    before,_:=DesyncStats()
    first:=[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    for _,part:=range [][]byte{first[:2],first[2:20],first[20:]} {
        if n,err:=conn.Write(part);err!=nil || n!=len(part) {t.Fatal(n,err)}
    }
    _ = incoming.SetReadDeadline(time.Now().Add(3*time.Second))
    got:=make([]byte,len(first))
    if _,err:=io.ReadFull(incoming,got);err!=nil || !bytes.Equal(got,first) {t.Fatal("split HTTP changed bytes",err)}
    after,_:=DesyncStats()
    if after!=before+1 {t.Fatal("fragmented HTTP did not receive existing split method")}
}

func TestHTTPHeaderWaitIsBoundedAndRawTCPUnchanged(t *testing.T) {
    for _,raw:=range []string{"SSH-2.0-example\r\n","GET / HTTP/1.1\r\nHost: partial"} {
        outgoing,incoming:=tcpCopyPair(t)
        conn:=&desyncConn{TCPConn:outgoing,mode:desyncMode{kind:desyncSplit}}
        if n,err:=conn.Write([]byte(raw));err!=nil || n!=len(raw) {t.Fatal(n,err)}
        _ = incoming.SetReadDeadline(time.Now().Add(3*time.Second))
        got:=make([]byte,len(raw))
        if _,err:=io.ReadFull(incoming,got);err!=nil || string(got)!=raw {t.Fatal("raw/partial TCP changed",err)}
        _=conn.Close()
    }
    if needsMoreFirstHTTP(make([]byte,16*1024)) || needsMoreFirstHTTP([]byte("SSH-2.0")) ||
        needsMoreFirstHTTP([]byte("GET /\r\n\r\n")) {t.Fatal("invalid header wait")}
}

func TestNewHTTPMethodNotAdmittedToLiveAutoOrModel(t *testing.T) {
    if localdpi.SupportsMethod(localdpi.HTTP,"http-hostcase") ||
        localdpi.NeuralIndex("http-hostcase",localdpi.HTTP)!=-1 {t.Fatal("unverified method enabled")}
    mode,ok,err:=parseDesyncTag(diagnosticTagPrefix+"http-hostcase")
    if err!=nil || !ok || mode.kind!=desyncHTTPHostCase {t.Fatal("explicit diagnostic tag unavailable")}
}
