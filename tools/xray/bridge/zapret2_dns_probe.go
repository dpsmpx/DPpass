//go:build linux

package bridge

// Fixed-target DNS-over-HTTPS differential diagnostic.
//
// Each resolver is contacted by a pinned, literal IPv4 address through a
// protected Xray test outbound. The provider's HTTPS identity is verified
// against its name. A verified DNS answer is then used only for a separate,
// certificate-verified probe of one allowlisted YouTube API hostname.
//
// No application DNS setting or regular VPN route is changed; plaintext
// DNS/53, arbitrary user hostnames and redirects are prohibited.
import (
    "bytes"
    "context"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "fmt"
    "io"
    "net"
    "net/http"
    "sync/atomic"
    "time"
    "sort"
    "strings"

    "github.com/miekg/dns"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
)

type fixedDoHProvider struct {
    address string
    host string
}

var zapret2DoHProviders = map[string]fixedDoHProvider{
    // IP bootstrap is fixed specifically to avoid dependence on any
    // potentially intercepted network/Android/system DNS response.
    "cloudflare": {"1.1.1.1", "cloudflare-dns.com"},
    "google": {"8.8.8.8", "dns.google"},
    "quad9": {"9.9.9.9", "dns.quad9.net"},
}

const zapret2DoHQuestion = "youtubei.googleapis.com."

type fixedDoHAnswer struct {
    ips []string
    fingerprint string // first 32 bits of SHA256 of sorted A RRset; not an IP
    status string
    httpStatus int
    protocol int
}

func publicIPv4Answers(reply *dns.Msg, question string) []string {
    if reply == nil || !reply.Response || reply.Rcode != dns.RcodeSuccess ||
        len(reply.Question) != 1 || reply.Question[0].Name != question ||
        reply.Question[0].Qtype != dns.TypeA { return nil }
    // A RR may point at a CNAME chain; allow at most 8 explicit steps.
    names := map[string]bool{strings.ToLower(question):true}
    for i:=0;i<8;i++ {
        grew:=false
        for _, rr:=range reply.Answer {
            if c,ok:=rr.(*dns.CNAME);ok && names[strings.ToLower(c.Hdr.Name)] {
                name:=strings.ToLower(c.Target)
                if !names[name] {names[name]=true;grew=true}
            }
        }
        if !grew { break }
    }
    seen:=map[string]bool{}
    ips:=make([]string,0,4)
    for _, rr:=range reply.Answer {
        a,ok:=rr.(*dns.A)
        if !ok || !names[strings.ToLower(a.Hdr.Name)] {continue}
        ip:=a.A.To4()
        if ip==nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {continue}
        value:=ip.String()
        if !seen[value] {seen[value]=true;ips=append(ips,value)}
        if len(ips)>=16 {break}
    }
    sort.Strings(ips)
    return ips
}

func fixedDoHReplyStatus(err error, ctx context.Context, phase string) string {
    if ctx.Err()!=nil {return "doh_timeout_"+phase}
    if err!=nil {return "doh_"+phase+"_failed"}
    return "doh_invalid"
}

// This TLS-verified DoH request must support HTTP/2. Some providers
// reject HTTP/1.1, so manual req.Write/ReadResponse is not an adequate test.
// The custom dialer uses ONLY the allowlisted literal bootstrap IPv4;
// neither system DNS nor normal VPN DNS is involved.
func resolveFixedDoH(ctx context.Context, inst *core.Instance, providerName string) fixedDoHAnswer {
    provider, ok := zapret2DoHProviders[providerName]
    if !ok { return fixedDoHAnswer{status:"invalid_target"} }
    msg:=new(dns.Msg)
    msg.SetQuestion(zapret2DoHQuestion,dns.TypeA)
    wire,err:=msg.Pack()
    if err!=nil { return fixedDoHAnswer{status:"doh_invalid"} }

    // Stage tracking distinguishes resolver dial, TLS and HTTP errors.
    var stage atomic.Int32
    stage.Store(1)
    var stopClosing func()
    tr:=&http.Transport{
        Proxy:nil,
        ForceAttemptHTTP2:true,
        DisableKeepAlives:true,
        MaxConnsPerHost:1,
        TLSClientConfig:&tls.Config{
            RootCAs:probeRoots, MinVersion:tls.VersionTLS12,
            ServerName:provider.host,
            NextProtos:[]string{"h2","http/1.1"},
        },
    }
    tr.DialTLSContext=func(dialCtx context.Context, network, addr string) (net.Conn,error) {
        // Reject alternative endpoints and redirects, even if a caller changes
        // the URL by accident. Every dial uses a known fixed IP.
        if addr!=provider.host+":443" || (network!="tcp" && network!="tcp4") {
            return nil,fmt.Errorf("unexpected DoH endpoint")
        }
        stage.Store(1)
        destination:=xnet.Destination{Network:xnet.Network_TCP,
            Address:xnet.ParseAddress(provider.address),Port:443}
        forced:=session.SetForcedOutboundTagToContext(dialCtx,zapret2PlainTag+"-ipv4")
        raw,dialErr:=core.Dial(forced,inst,destination)
        if dialErr!=nil {return nil,dialErr}
        // core.Dial's protected socket is also closed when the request times
        // out, rather than lingering through a blocked TLS handshake.
        done:=make(chan struct{})
        stopClosing=func(){close(done)}
        go func(){
            select {case <-dialCtx.Done():_=raw.Close();case <-done:}
        }()
        stage.Store(2)
        conn:=tls.Client(raw,tr.TLSClientConfig.Clone())
        if err:=conn.HandshakeContext(dialCtx);err!=nil {
            _=conn.Close()
            return nil,err
        }
        stage.Store(3)
        return conn,nil
    }
    defer func(){
        tr.CloseIdleConnections()
        if stopClosing!=nil {stopClosing()}
    }()
    client:=&http.Client{
        Transport:tr,
        CheckRedirect:func(_ *http.Request,_ []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    req,err:=http.NewRequestWithContext(ctx,http.MethodPost,
        "https://"+provider.host+"/dns-query",bytes.NewReader(wire))
    if err!=nil {return fixedDoHAnswer{status:"doh_invalid"}}
    req.Header.Set("Content-Type","application/dns-message")
    req.Header.Set("Accept","application/dns-message")
    req.Header.Set("Accept-Encoding","identity")
    resp,err:=client.Do(req)
    if err!=nil {
        phase:="headers"
        switch stage.Load() {case 1:phase="dial";case 2:phase="tls"}
        return fixedDoHAnswer{status:fixedDoHReplyStatus(err,ctx,phase)}
    }
    defer resp.Body.Close()
    answer:=fixedDoHAnswer{httpStatus:resp.StatusCode,protocol:resp.ProtoMajor}
    if resp.StatusCode!=http.StatusOK {
        answer.status="doh_http_status"
        return answer
    }
    if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")),
        "application/dns-message") {
        answer.status="doh_invalid"
        return answer
    }
    body,err:=io.ReadAll(io.LimitReader(resp.Body,4097))
    if err!=nil {
        answer.status=fixedDoHReplyStatus(err,ctx,"body")
        return answer
    }
    if len(body)>4096 {
        answer.status="doh_invalid"
        return answer
    }
    parsed:=new(dns.Msg)
    if err=parsed.Unpack(body);err!=nil {
        answer.status="doh_invalid"
        return answer
    }
    if parsed.Id!=msg.Id || parsed.Truncated || parsed.Rcode!=dns.RcodeSuccess {
        answer.status="doh_invalid"
        return answer
    }
    ips:=publicIPv4Answers(parsed,zapret2DoHQuestion)
    if len(ips)==0 {
        answer.status="doh_no_ipv4"
        return answer
    }
    sum:=sha256.Sum256([]byte(strings.Join(ips,",")))
    answer.ips=ips
    answer.fingerprint=hex.EncodeToString(sum[:4])
    answer.status="ok"
    return answer
}

func validateFixedDoHProvider(name string) bool {
    _,ok:=zapret2DoHProviders[name]
    return ok
}

// A maximum per-IP deadline stops a single blackholed endpoint from
// consuming the entire differential test. Check *all* returned IPv4 A
// addresses (up to 16) and keep counters without exposing individual IPs.
const fixedDoHIPTimeout=2100*time.Millisecond
func probeAllDNSIPs(ctx context.Context, ips []string,
    check func(context.Context,string) Zapret2HTTPSResult) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"timeout_dial"}
    bestScore:=-1
    for index,ip:=range ips {
        if ctx.Err()!=nil {break}
        perIP:=fixedDoHIPTimeout
        if deadline,ok:=ctx.Deadline();ok {
            remaining:=time.Until(deadline)
            each:=remaining/time.Duration(len(ips)-index)
            if each<perIP {perIP=each}
        }
        if perIP<400*time.Millisecond {break}
        oneCtx,cancel:=context.WithTimeout(ctx,perIP)
        result:=check(oneCtx,ip)
        cancel()
        out.DnsChecked++
        // A successful TLS verification is any state reached past the
        // handshake; the probe exposes no raw payloads or remote IPs.
        tlsOK:=result.TLSVerified
        if tlsOK {out.DnsTLSReady++}
        if result.Outcome=="http_reachable" {out.DnsHTTPReady++}
        score:=0
        if result.Outcome=="timeout_tls" {score=1}
        if tlsOK {score=2}
        if result.Outcome=="http_reachable" {score=3}
        if score>bestScore {
            bestScore=score
            out.Outcome=result.Outcome
            out.HTTPStatus=result.HTTPStatus
            out.BodyBytes=result.BodyBytes
        }
    }
    return out
}

// Handles a test-only DoH arm without exposing raw IPs or altering the
// global DNS policy. HTTPS uses youtubei.googleapis.com Host and SNI with
// full certificate verification for every selected IPv4.
func probeWithFixedDoH(ctx context.Context, inst *core.Instance, strategy, providerName string,
    target zapret2TestTarget) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"doh_invalid",DnsFingerprint:"-",DoHProbe:true}
    if !validateFixedDoHProvider(providerName) {return out}
    answer:=resolveFixedDoH(ctx,inst,providerName)
    out.DoHHTTPStatus=answer.httpStatus
    out.DoHProtocol=answer.protocol
    if answer.status!="ok" {out.Outcome=answer.status;return out}
    out.DnsFingerprint=answer.fingerprint
    out.DnsAnswers=len(answer.ips)
    tag:=zapret2TestStrategies[strategy]+"-ipv4"
    targetProbes:=probeAllDNSIPs(ctx,answer.ips,
        func(oneCtx context.Context,ip string) Zapret2HTTPSResult {
            dest:=xnet.Destination{Network:xnet.Network_TCP,
                Address:xnet.ParseAddress(ip),Port:443}
            forced:=session.SetForcedOutboundTagToContext(oneCtx,tag)
            conn,err:=core.Dial(forced,inst,dest)
            if err!=nil {
                state:="dial_failed"
                if oneCtx.Err()!=nil {state="timeout_dial"}
                return Zapret2HTTPSResult{Outcome:state}
            }
            defer conn.Close()
            done:=make(chan struct{})
            defer close(done)
            go func(){
                select {case <-oneCtx.Done():_=conn.Close();case <-done:}
            }()
            return probeHTTPSWithConn(oneCtx,conn,target)
        })
    targetProbes.DoHProbe=true
    targetProbes.DnsFingerprint=out.DnsFingerprint
    targetProbes.DnsAnswers=out.DnsAnswers
    targetProbes.DoHHTTPStatus=out.DoHHTTPStatus
    targetProbes.DoHProtocol=out.DoHProtocol
    return targetProbes
}
