//go:build linux || windows

package bridge

import (
    "bufio"
    "context"
    "crypto/tls"
    "errors"
    "io"
    "net"
    "net/http"
    "time"

    "github.com/miekg/dns"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
)

// This bounded fixed public control enters the production dispatcher with
// the TUN tag. Unlike protected per-IP DPTS, it uses the configured virtual
// DNS outbound and ordinary routing. It does not traverse Android's TUN fd.
const localControlTarget = "local-control://google"
const localControlHost = "www.google.com."

func localControlA(reply *dns.Msg, id uint16) net.IP {
    if reply == nil || !reply.Response || reply.Id != id || reply.Rcode != dns.RcodeSuccess ||
        len(reply.Question) != 1 || reply.Question[0].Name != localControlHost ||
        reply.Question[0].Qtype != dns.TypeA { return nil }
    for _, rr := range reply.Answer {
        if a, ok := rr.(*dns.A); ok && a.Hdr.Name == localControlHost &&
            a.A.To4() != nil && a.A.IsGlobalUnicast() && !a.A.IsPrivate() {
            return a.A.To4()
        }
    }
    return nil
}

func localControlDial(ctx context.Context, inst *core.Instance, network xnet.Network, host string, port int, sniff bool) (net.Conn,error) {
    ctx = session.ContextWithInbound(ctx, &session.Inbound{Tag:"tun-in"})
    if sniff {
        ctx = session.ContextWithContent(ctx, &session.Content{SniffingRequest:session.SniffingRequest{
            Enabled:true, OverrideDestinationForProtocol:[]string{"tls"}, RouteOnly:true,
        }})
    }
    conn, err := core.Dial(ctx,inst,xnet.Destination{Network:network,Address:xnet.ParseAddress(host),Port:xnet.Port(port)})
    if err == nil { go func(){ <-ctx.Done(); _ = conn.Close() }() }
    return conn,err
}

func probeLocalControl(inst *core.Instance, timeout time.Duration) ProbeResult {
    start:=time.Now()
    if timeout <= 0 { return ProbeResult{Outcome:ProbeContract,Err:errors.New("invalid_timeout")} }
    ctx,cancel:=context.WithTimeout(context.Background(),timeout)
    defer cancel()
    fail:=func(stage string, outcome ProbeOutcome) ProbeResult {
        return ProbeResult{Outcome:outcome,Elapsed:time.Since(start),Err:errors.New(stage)}
    }
    query:=new(dns.Msg)
    query.SetQuestion(localControlHost,dns.TypeA)
    wire,err:=query.Pack()
    if err!=nil { return fail("dns_encode",ProbeContract) }
    dc,err:=localControlDial(ctx,inst,xnet.Network_UDP,"172.19.0.2",53,false)
    if err!=nil { return fail("virtual_dns_dial",ProbeUnreachable) }
    defer dc.Close()
    if _,err=dc.Write(wire);err!=nil { return fail("virtual_dns_write",ProbeUnreachable) }
    buf:=make([]byte,65535)
    n,err:=dc.Read(buf)
    if err!=nil { return fail("virtual_dns_read",ProbeStalled) }
    reply:=new(dns.Msg)
    if reply.Unpack(buf[:n])!=nil { return fail("virtual_dns_invalid",ProbeBadAnswer) }
    ip:=localControlA(reply,query.Id)
    if ip==nil { return fail("virtual_dns_no_a",ProbeBadAnswer) }
    raw,err:=localControlDial(ctx,inst,xnet.Network_TCP,ip.String(),443,true)
    if err!=nil { return fail("routed_tcp_dial",ProbeUnreachable) }
    defer raw.Close()
    tc:=tls.Client(raw,&tls.Config{ServerName:"www.google.com",RootCAs:probeRoots,MinVersion:tls.VersionTLS12,NextProtos:[]string{"http/1.1"}})
    if tc.HandshakeContext(ctx)!=nil { return fail("routed_tls",ProbeTLS) }
    req,err:=http.NewRequestWithContext(ctx,http.MethodGet,"https://www.google.com/",nil)
    if err!=nil { return fail("http_request",ProbeContract) }
    req.Close=true
    if req.Write(tc)!=nil { return fail("http_write",ProbeStalled) }
    resp,err:=http.ReadResponse(bufio.NewReader(tc),req)
    if err!=nil { return fail("http_headers",ProbeStalled) }
    defer resp.Body.Close()
    if resp.StatusCode!=http.StatusOK { return fail("http_non_200",ProbeBadAnswer) }
    body,err:=io.ReadAll(io.LimitReader(resp.Body,256))
    if err!=nil || len(body)<128 { return fail("http_short_body",ProbeBadAnswer) }
    return ProbeResult{Outcome:ProbeOK,Elapsed:time.Since(start),Received:int64(len(body))}
}
