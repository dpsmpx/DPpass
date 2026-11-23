//go:build linux

package bridge

import (
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "io"
    "net"
    "net/http"
    "net/http/httptest"
    "time"
    "regexp"
    "strings"
    "testing"

    "github.com/miekg/dns"
)

func TestFixedDoHProvidersUseLiteralBootstrapAndSafeNames(t *testing.T) {
    if len(zapret2DoHProviders)!=3 {t.Fatal("expected three pinned providers")}
    for _,id:=range []string{"cloudflare","google","quad9"} {
        p,ok:=zapret2DoHProviders[id]
        if !ok || net.ParseIP(p.address).To4()==nil ||
            !strings.Contains(p.host,".") {t.Fatalf("invalid DoH provider %s",id)}
    }
    for _,bad:=range []string{"", "https://evil.test", "../cloudflare", "cloudflare:53"} {
        if validateFixedDoHProvider(bad) {t.Fatalf("accepted %q",bad)}
        if got:=ProbeZapret2HTTPS("fake-5","youtube_api_dns_"+bad,8_000_000_000);
            got.Outcome!="invalid_target" {t.Fatalf("allowed %q: %s",bad,got.Outcome)}
    }
}

func TestFixedDoHDNSAnswerRejectsPrivateAndUnrelatedIPs(t *testing.T) {
    msg:=new(dns.Msg)
    msg.SetQuestion(zapret2DoHQuestion,dns.TypeA)
    msg.Response=true
    msg.Answer=[]dns.RR{
        &dns.A{Hdr:dns.RR_Header{Name:zapret2DoHQuestion,Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.ParseIP("8.8.8.8")},
        &dns.A{Hdr:dns.RR_Header{Name:zapret2DoHQuestion,Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.ParseIP("10.0.0.1")},
        &dns.A{Hdr:dns.RR_Header{Name:"unrelated.example.",Rrtype:dns.TypeA,Class:dns.ClassINET},A:net.ParseIP("1.1.1.1")},
    }
    got:=publicIPv4Answers(msg,zapret2DoHQuestion)
    if len(got)!=1 || got[0]!="8.8.8.8" {t.Fatalf("filtered A records: %v",got)}
    msg.Rcode=dns.RcodeNameError
    if got=publicIPv4Answers(msg,zapret2DoHQuestion);len(got)!=0 {
        t.Fatal("NXDOMAIN returned IP addresses")
    }
}

func TestFixedDoHWireContainsNoRawIPv4(t *testing.T) {
    r:=Zapret2HTTPSResult{Outcome:"timeout_tls",Elapsed:8_000_000_000,
        DnsFingerprint:"12abcd34",DnsAnswers:4}
    wire:=string(r.Wire())
    if !regexp.MustCompile("^v2\\ttimeout_tls\\t0\\t0\\t8000\\t0\\t0\\t12abcd34\\t4$").MatchString(wire) {
        t.Fatalf("invalid v2 wire: %q",wire)
    }
    if strings.Contains(wire,"youtubei")||strings.Contains(wire,"8.8.8.8") {
        t.Fatal("sensitive DNS target leaked")
    }
    if !strings.HasPrefix(string(Zapret2HTTPSResult{Outcome:"ok"}.Wire()),"v1\t"){
        t.Fatal("ordinary probe should retain v1 protocol")
    }
}

func TestFixedDoHQuestionWhitelistAndQuad9HTTP2Only(t *testing.T) {
    if !fixedDoHUsesHTTP2("quad9") || fixedDoHUsesHTTP2("google") ||
        fixedDoHUsesHTTP2("cloudflare") {t.Fatal("Quad9-only ALPN selection changed")}
    for _,question:=range []string{zapret2DoHQuestion,zapret2ControlDoHQuestion} {
        msg:=newFixedDoHQuestionFor(question)
        if msg==nil || msg.Id!=0 || len(msg.Question)!=1 ||
            msg.Question[0].Name!=question || msg.Question[0].Qtype!=dns.TypeA {
            t.Fatalf("bad fixed DoH question %q",question)
        }
    }
    for _,question:=range []string{"", "www.google.com", "evil.example.", ".", "../dns-query"} {
        if newFixedDoHQuestionFor(question)!=nil {t.Fatalf("unapproved DoH question %q",question)}
    }
}

func TestQuad9StyleDoHHTTP2ExchangeOnVerifiedPinnedSocket(t *testing.T) {
    // Local HTTPS server: proves that the actual exchange helper sends
    // binary RFC8484 POST via ALPN h2 over an already verified TLS socket.
    // No device network, test resolver, or external DNS is contacted.
    requestOk:=false
    srv:=httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
        if r.ProtoMajor!=2 || r.Method!=http.MethodPost || r.URL.Path!="/dns-query" ||
            r.Header.Get("Content-Type")!="application/dns-message" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        wire,err:=io.ReadAll(io.LimitReader(r.Body,4097))
        if err!=nil || len(wire)>4096 {w.WriteHeader(http.StatusBadRequest);return}
        m:=new(dns.Msg)
        if m.Unpack(wire)!=nil || m.Id!=0 || len(m.Question)!=1 ||
            m.Question[0].Name!=zapret2ControlDoHQuestion {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        requestOk=true
        response:=new(dns.Msg)
        response.SetReply(m)
        response.Answer=[]dns.RR{&dns.A{Hdr:dns.RR_Header{
            Name:zapret2ControlDoHQuestion,Rrtype:dns.TypeA,Class:dns.ClassINET,
        },A:net.ParseIP("8.8.8.8")}}
        body,_:=response.Pack()
        w.Header().Set("Content-Type","application/dns-message")
        _,_=w.Write(body)
    }))
    srv.EnableHTTP2=true
    srv.StartTLS()
    defer srv.Close()
    roots:=x509.NewCertPool()
    roots.AddCert(srv.Certificate())
    raw,err:=net.DialTimeout("tcp",srv.Listener.Addr().String(),time.Second)
    if err!=nil {t.Fatal(err)}
    defer raw.Close()
    host:="localhost"
    if len(srv.Certificate().DNSNames)>0 {host=srv.Certificate().DNSNames[0]}
    tlsConn:=tls.Client(raw,&tls.Config{
        ServerName:host,RootCAs:roots,MinVersion:tls.VersionTLS12,NextProtos:[]string{"h2"},
    })
    defer tlsConn.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
    defer cancel()
    if err:=tlsConn.HandshakeContext(ctx);err!=nil {t.Fatal(err)}
    if tlsConn.ConnectionState().NegotiatedProtocol!="h2" {t.Fatal("HTTP2 ALPN absent")}
    wire,err:=newFixedDoHQuestionFor(zapret2ControlDoHQuestion).Pack()
    if err!=nil {t.Fatal(err)}
    req,err:=http.NewRequestWithContext(ctx,http.MethodPost,
        "https://"+host+"/dns-query",bytes.NewReader(wire))
    if err!=nil {t.Fatal(err)}
    req.Header.Set("Content-Type","application/dns-message")
    req.Header.Set("Accept","application/dns-message")
    req.Header.Set("Accept-Encoding","identity")
    resp,status:=fixedDoHExchange(req,tlsConn,true)
    if status!="" {t.Fatalf("HTTP2 exchange failed: %s",status)}
    defer resp.Body.Close()
    if resp.StatusCode!=200 {t.Fatalf("unexpected HTTP %d",resp.StatusCode)}
    body,err:=io.ReadAll(io.LimitReader(resp.Body,4097))
    if err!=nil {t.Fatal(err)}
    answer:=new(dns.Msg)
    if err=answer.Unpack(body);err!=nil {t.Fatal(err)}
    if !requestOk || len(publicIPv4Answers(answer,zapret2ControlDoHQuestion))!=1 {
        t.Fatal("HTTP2 DoH request or response was not parsed")
    }
}
