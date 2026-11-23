//go:build linux

package bridge

import (
    "net"
    "context"
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

func TestProbeAllDNSIPsAttemptsEachAddressAndAggregatesVerifiedTLS(t *testing.T) {
    ips:=[]string{"8.8.8.1","8.8.8.2","8.8.8.3","8.8.8.4",
        "8.8.8.5","8.8.8.6","8.8.8.7","8.8.8.8"}
    called:=map[string]bool{}
    ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
    defer cancel()
    result:=probeAllDNSIPs(ctx,ips,func(_ context.Context,ip string) Zapret2HTTPSResult {
        called[ip]=true
        if ip=="8.8.8.7" {
            return Zapret2HTTPSResult{Outcome:"http_reachable",
                HTTPStatus:403,TLSVerified:true}
        }
        if ip=="8.8.8.8" {
            return Zapret2HTTPSResult{Outcome:"http_failed",TLSVerified:true}
        }
        return Zapret2HTTPSResult{Outcome:"timeout_tls"}
    })
    if len(called)!=8 || result.DnsChecked!=8 || result.DnsTLSReady!=2 ||
        result.DnsHTTPReady!=1 || result.Outcome!="http_reachable" ||
        result.HTTPStatus!=403 {
        t.Fatalf("did not test all A records: visited=%d got=%+v",len(called),result)
    }
}

func TestProbeAllDNSIPsNoTLSDoesNotClaimHTTP(t *testing.T) {
    result:=probeAllDNSIPs(context.Background(),[]string{"8.8.8.1","8.8.8.2"},
        func(_ context.Context,_ string) Zapret2HTTPSResult {
            return Zapret2HTTPSResult{Outcome:"timeout_tls"}
        })
    if result.DnsChecked!=2 || result.DnsTLSReady!=0 ||
        result.DnsHTTPReady!=0 || result.Outcome!="timeout_tls" {
        t.Fatalf("false success: %+v",result)
    }
}

func TestDoHV3WireCarriesResolverStatusAndAllAResults(t *testing.T) {
    r:=Zapret2HTTPSResult{Outcome:"doh_http_status", DoHProbe:true,
        DoHHTTPStatus:505,DoHProtocol:1,DnsFingerprint:"-"}
    wire:=string(r.Wire())
    expected:="v3\tdoh_http_status\t0\t0\t0\t0\t0\t-\t0\t505\t1\t0\t0\t0"
    if wire!=expected {t.Fatalf("wire=%q want %q",wire,expected)}
    r=Zapret2HTTPSResult{Outcome:"timeout_tls",DoHProbe:true,
        DnsFingerprint:"6f706c12",DnsAnswers:8,DnsChecked:8,
        DnsTLSReady:0,DnsHTTPReady:0,DoHHTTPStatus:200,DoHProtocol:2}
    wire=string(r.Wire())
    if !strings.HasSuffix(wire,"\t200\t2\t8\t0\t0") ||
        !strings.HasPrefix(wire,"v3\ttimeout_tls\t") {
        t.Fatalf("bad full RRset wire: %q",wire)
    }
}
