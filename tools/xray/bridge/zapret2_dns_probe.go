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
    "bufio"
    "bytes"
    "context"
    "crypto/sha256"
    "crypto/tls"
    "encoding/hex"
    "io"
    "net/http"

    "golang.org/x/net/http2"
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
const zapret2ControlDoHQuestion = "www.google.com."

type fixedDoHAnswer struct {
    ips []string
    fingerprint string // first 32 bits of SHA256 of sorted A RRset; not an IP
    status string
    httpStatus int
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

// RFC 8484 requires zero DNS message IDs in DoH requests. Some
// resolvers (including Quad9) reject otherwise-valid queries with HTTP 400.
func newFixedDoHQuestion() *dns.Msg {
    return newFixedDoHQuestionFor(zapret2DoHQuestion)
}
// An allowlist is enforced before a DNS question can reach a resolver.
// Only two public, nonpersonal domain names are used in these tests.
func newFixedDoHQuestionFor(question string) *dns.Msg {
    if question!=zapret2DoHQuestion && question!=zapret2ControlDoHQuestion {
        return nil
    }
    msg:=new(dns.Msg)
    msg.SetQuestion(question,dns.TypeA)
    msg.Id=0
    return msg
}

func fixedDoHUsesHTTP2(providerName string) bool {return providerName=="quad9"}

func fixedDoHReplyStatus(err error, ctx context.Context, phase string) string {
    if ctx.Err()!=nil {return "doh_timeout_"+phase}
    if err!=nil {return "doh_"+phase+"_failed"}
    return "doh_invalid"
}

// Return a bound, anonymized address-set fingerprint, never raw IPs to Java.
// Each HTTPS request and the downstream TLS probe share the same deadline.
func resolveFixedDoH(ctx context.Context, inst *core.Instance, providerName string) fixedDoHAnswer {
    return resolveFixedDoHForQuestion(ctx,inst,providerName,zapret2DoHQuestion)
}
func resolveFixedDoHForQuestion(ctx context.Context, inst *core.Instance, providerName, question string) fixedDoHAnswer {
    provider,ok:=zapret2DoHProviders[providerName]
    if !ok {return fixedDoHAnswer{status:"invalid_target"}}
    msg:=newFixedDoHQuestionFor(question)
    if msg==nil {return fixedDoHAnswer{status:"invalid_target"}}
    wire,err:=msg.Pack()
    if err!=nil {return fixedDoHAnswer{status:"doh_invalid"}}

    // DoH uses HTTPS-over-protected-TCP, not UDP/53. No system DNS needed.
    destination:=xnet.Destination{Network:xnet.Network_TCP,
        Address:xnet.ParseAddress(provider.address),Port:443}
    forced:=session.SetForcedOutboundTagToContext(ctx,zapret2PlainTag+"-ipv4")
    raw,err:=core.Dial(forced,inst,destination)
    if err!=nil {return fixedDoHAnswer{status:fixedDoHReplyStatus(err,ctx,"dial")}}
    defer raw.Close()
    done:=make(chan struct{})
    defer close(done)
    go func() {select {case <-ctx.Done(): _=raw.Close();case <-done:}}()

    // Quad9 responds HTTP 505 to HTTP/1.1 since the service requires H2.
    // Other providers retain the previous HTTP/1.1 baseline so only the
    // necessary protocol changes; no global Android/VPN DNS is modified.
    useH2:=fixedDoHUsesHTTP2(providerName)
    alpns:=[]string{"http/1.1"}
    if useH2 {alpns=[]string{"h2"}}
    tlsConn:=tls.Client(raw,&tls.Config{ServerName:provider.host,
        RootCAs:probeRoots,MinVersion:tls.VersionTLS12,NextProtos:alpns})
    defer tlsConn.Close()
    if err=tlsConn.HandshakeContext(ctx);err!=nil {
        return fixedDoHAnswer{status:fixedDoHReplyStatus(err,ctx,"tls")}
    }
    if useH2 && tlsConn.ConnectionState().NegotiatedProtocol!="h2" {
        return fixedDoHAnswer{status:"doh_h2_not_negotiated"}
    }
    req,err:=http.NewRequestWithContext(ctx,http.MethodPost,
        "https://"+provider.host+"/dns-query",bytes.NewReader(wire))
    if err!=nil {return fixedDoHAnswer{status:"doh_invalid"}}
    req.Header.Set("Content-Type","application/dns-message")
    req.Header.Set("Accept","application/dns-message")
    req.Header.Set("Accept-Encoding","identity")
    req.Close=true
    resp,status:=fixedDoHExchange(req,tlsConn,useH2)
    if status!="" {return fixedDoHAnswer{status:status}}
    defer resp.Body.Close()
    if resp.StatusCode != http.StatusOK {return fixedDoHAnswer{status:"doh_http_status",httpStatus:resp.StatusCode}}
    if !strings.HasPrefix(strings.ToLower(resp.Header.Get("Content-Type")),
        "application/dns-message") {return fixedDoHAnswer{status:"doh_invalid"}}
    body,err:=io.ReadAll(io.LimitReader(resp.Body,4097))
    if err!=nil {return fixedDoHAnswer{status:fixedDoHReplyStatus(err,ctx,"body")}}
    if len(body)>4096 {return fixedDoHAnswer{status:"doh_invalid"}}
    parsed:=new(dns.Msg)
    if err=parsed.Unpack(body);err!=nil {return fixedDoHAnswer{status:"doh_invalid"}}
    if parsed.Id!=msg.Id || parsed.Truncated || parsed.Rcode!=dns.RcodeSuccess {
        return fixedDoHAnswer{status:"doh_invalid"}
    }
    ips:=publicIPv4Answers(parsed,question)
    if len(ips)==0 {return fixedDoHAnswer{status:"doh_no_ipv4"}}
    sum:=sha256.Sum256([]byte(strings.Join(ips,",")))
    return fixedDoHAnswer{ips:ips,fingerprint:hex.EncodeToString(sum[:4]),status:"ok",httpStatus:200}
}

// The same single protected TLS connection is used for both HTTP versions.
// This helper has no Dial call: it cannot fall back to unprotected Android
// sockets or system DNS if an HTTP/2 attempt fails.
func fixedDoHExchange(req *http.Request, tlsConn *tls.Conn, useH2 bool) (*http.Response,string) {
    if useH2 {
        client,err:=(&http2.Transport{}).NewClientConn(tlsConn)
        if err!=nil {return nil,"doh_h2_failed"}
        defer client.Close()
        resp,err:=client.RoundTrip(req)
        if err!=nil {return nil,fixedDoHReplyStatus(err,req.Context(),"headers")}
        // Closing the HTTP2 transport after RoundTrip would close the
        // response body too early; instead hand the response back with the
        // underlying TLS socket lifetime owned by resolveFixedDoH.
        return resp,""
    }
    if err:=req.Write(tlsConn);err!=nil {
        return nil,fixedDoHReplyStatus(err,req.Context(),"write")
    }
    resp,err:=http.ReadResponse(bufio.NewReader(tlsConn),req)
    if err!=nil {return nil,fixedDoHReplyStatus(err,req.Context(),"headers")}
    return resp,""
}

func validateFixedDoHProvider(name string) bool {
    _,ok:=zapret2DoHProviders[name]
    return ok
}

// Handles a test-only DoH arm without exposing raw IPs or altering the
// global DNS policy. HTTPS is still sent with youtubei.googleapis.com Host
// and SNI, and its certificate is fully checked for that original host.
func probeWithFixedDoH(ctx context.Context, inst *core.Instance, strategy, providerName string,
    target zapret2TestTarget) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"doh_invalid",DnsFingerprint:"-",DnsAnswers:0}
    if !validateFixedDoHProvider(providerName) {return out}
    answer:=resolveFixedDoH(ctx,inst,providerName)
    if answer.status!="ok" {out.Outcome=answer.status;out.HTTPStatus=answer.httpStatus;return out}
    out.DnsFingerprint=answer.fingerprint
    out.DnsAnswers=len(answer.ips)
    // Select a stable IPv4 from each authenticated DNS answer set. A result
    // is valid only for that IP; differing sets are exposed by fingerprint.
    ip:=answer.ips[0]
    tag:=zapret2TestStrategies[strategy]+"-ipv4"
    dest:=xnet.Destination{Network:xnet.Network_TCP,
        Address:xnet.ParseAddress(ip),Port:443}
    forced:=session.SetForcedOutboundTagToContext(ctx,tag)
    conn,err:=core.Dial(forced,inst,dest)
    if err!=nil {
        out.Outcome="dial_failed"
        if ctx.Err()!=nil {out.Outcome="timeout_dial"}
        return out
    }
    defer conn.Close()
    done:=make(chan struct{})
    defer close(done)
    go func() {select {case <-ctx.Done():_=conn.Close();case <-done:}}()
    downstream:=probeHTTPSWithConn(ctx,conn,target)
    downstream.DnsFingerprint=out.DnsFingerprint
    downstream.DnsAnswers=out.DnsAnswers
    return downstream
}

