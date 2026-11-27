//go:build linux

package bridge

import (
    "bufio"
    "bytes"
    "io"
    "net"
    "net/http"
    "time"
)

// Fixed loopback-only regression through the actual TCP write adapter.
// No DNS, external address, user payload, Xray routing or model observation.
// The legacy JNI probe envelope carries a separate non-HTTPS result code.
func probeLocalHTTPHostCase(method string, timeout time.Duration) Zapret2HTTPSResult {
    started:=time.Now()
    out:=Zapret2HTTPSResult{Outcome:"invalid_strategy"}
    if method!="plain" && method!="http-hostcase" && method!="http-hostows" {return out}
    if timeout<time.Second || timeout>5*time.Second {
        out.Outcome="invalid_timeout"
        return out
    }
    counters:=&diagnosticRequestCounters{}
    finish:=func(outcome string) Zapret2HTTPSResult {
        out.Outcome=outcome
        return finalizeHTTPSDiagnostic(out,time.Since(started),counters)
    }
    deadline:=started.Add(timeout)
    listener,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.IPv4(127,0,0,1)})
    if err!=nil {return finish("dial_failed")}
    defer listener.Close()
    if err:=listener.SetDeadline(deadline);err!=nil {return finish("dial_failed")}
    dialer:=net.Dialer{Deadline:deadline}
    raw,err:=dialer.Dial("tcp4",listener.Addr().String())
    if err!=nil {return finish("dial_failed")}
    defer raw.Close()
    client,ok:=raw.(*net.TCPConn)
    if !ok {return finish("local_http_mismatch")}
    server,err:=listener.AcceptTCP()
    if err!=nil {return finish("dial_failed")}
    defer server.Close()
    if client.SetDeadline(deadline)!=nil || server.SetDeadline(deadline)!=nil {
        return finish("dial_failed")
    }
    if !client.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() ||
        !server.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
        return finish("local_http_mismatch")
    }
    original:=[]byte("POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody")
    expected:=bytes.Clone(original)
    var writer io.Writer=client
    if method!="plain" {
        kind:=desyncHTTPHostCase
        if method=="http-hostcase" {
            expected=bytes.Replace(expected,[]byte("\r\nHost:"),[]byte("\r\nhOsT:"),1)
        } else {
            kind=desyncHTTPHostOWS
            expected=bytes.Replace(expected,[]byte("\r\nHost: "),[]byte("\r\nHost:\t"),1)
        }
        conn:=&desyncConn{TCPConn:client,mode:desyncMode{kind:kind},
            diagnostic:true,request:counters}
        defer conn.Close()
        writer=conn
    }
    n,err:=writer.Write(original)
    if err!=nil || n!=len(original) {return finish("request_failed")}
    // EOF confirms exact total length, not only a matching prefix.
    if err:=client.CloseWrite();err!=nil {return finish("request_failed")}
    got,err:=io.ReadAll(io.LimitReader(server,int64(len(expected)+1)))
    if err!=nil || !bytes.Equal(got,expected) {return finish("local_http_mismatch")}
    request,err:=http.ReadRequest(bufio.NewReader(bytes.NewReader(got)))
    if err!=nil {return finish("local_http_mismatch")}
    defer request.Body.Close()
    body,err:=io.ReadAll(io.LimitReader(request.Body,5))
    if err!=nil || request.Host!="example.com" || request.Method!="POST" ||
        request.RequestURI!="/self-check" || request.Proto!="HTTP/1.1" ||
        string(body)!="body" {return finish("local_http_mismatch")}
    result:=finish("local_http_verified")
    if method=="plain" && (result.AppliedDelta!=0 || result.SkippedDelta!=0) ||
        method!="plain" && (result.AppliedDelta!=1 || result.SkippedDelta!=0) {
        result.Outcome="local_http_mismatch"
    }
    return result
}
