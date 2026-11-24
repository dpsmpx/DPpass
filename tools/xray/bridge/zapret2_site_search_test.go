//go:build linux

package bridge

import (
    "testing"
    "time"

    "github.com/xtls/xray-core/core"
)

func TestSiteSearchHostAndRequestGrammarRejectsPrivateOrUserURLs(t *testing.T) {
    for _,host:=range []string{
        "www.youtube.com","cdn.example.org","xn--e1afmkfd.xn--p1ai",
        "news.example.co.uk",
    } {
        if !validOptInSiteHost(host) {t.Fatalf("safe host rejected: %s",host)}
        for _,name:=range []string{
            "site_prepare:"+host,"site_apply:"+host,
            "site_ip00_a1_:"+host,"site_ip01_a3_:"+host,
            "site_quic_ip00_a2_:"+host,
        } {
            if _,ok:=parseSiteSearchRequest(name);!ok {t.Fatalf("valid request rejected: %s",name)}
        }
    }
    for _,host:=range []string{
        "localhost","host.local","printer.lan","router.internal",
        "example.test","example.onion","home.arpa",
        "127.0.0.1","1.1.1.1","192.168.0.1",
        "example.com:443","https://example.com/","example.com/path",
        "example.com?token=secret","example.com#fragment",
        "EXAMPLE.COM","-invalid.example.org","bad..example.net",
    } {
        if validOptInSiteHost(host) {t.Fatalf("unsafe hostname accepted: %s",host)}
        if _,ok:=parseSiteSearchRequest("site_prepare:"+host);ok {
            t.Fatalf("unsafe request accepted: %s",host)
        }
    }
    for _,name:=range []string{
        "site_ip02_a1_:example.org","site_ip00_a0_:example.org",
        "site_ip00_a4_:example.org","site_ip00_a1:example.org",
        "site_quic_ip99_a3_:example.org",
        "site_ip00_a1_:example.org/secret","site_auto:example.org",
    } {
        if _,ok:=parseSiteSearchRequest(name);ok {
            t.Fatalf("unbounded request accepted: %s",name)
        }
    }
}
func TestSiteSearchNeverDialsSpecialUseIPv4(t *testing.T) {
    for _,ip:=range []string{
        "0.0.0.0","10.0.0.1","100.64.0.1","127.0.0.1",
        "169.254.1.2","172.16.1.2","192.168.1.1","192.0.0.1",
        "198.18.0.1","198.51.100.7","203.0.113.5",
        "224.0.0.1","240.0.0.1","255.255.255.255","::1",
    }{
        if sitePublicIPv4(ip) {t.Errorf("private/reserved IP accepted %s",ip)}
    }
    for _,ip:=range []string{"1.1.1.1","8.8.8.8","93.184.216.34"} {
        if !sitePublicIPv4(ip) {t.Errorf("public IP rejected %s",ip)}
    }
}

func newSiteSearchTestRun(t *testing.T,host string,ips []string) (*core.Instance,uint64) {
    t.Helper()
    if err:=zapret2Auto.configureHosts("");err!=nil {t.Fatal(err)}
    inst:=&core.Instance{}
    gen:=zapret2Auto.generationSnapshot()
    siteSearchState.Lock()
    siteSearchState.current=&siteSearchRun{
        instance:inst,generation:gen,host:host,prepared:time.Now(),
        answer:fixedDoHAnswer{ips:ips,fingerprint:"abcdef12",status:"ok",httpStatus:200},
        trials:make(map[string]*siteSearchTrial),
    }
    siteSearchState.Unlock()
    t.Cleanup(func() {
        siteSearchState.Lock()
        siteSearchState.current=nil
        siteSearchState.Unlock()
        _=zapret2Auto.configureHosts("")
    })
    return inst,gen
}
func TestSiteSearchCommitRequiresIndependentThreeOfThreeAtEachAddress(t *testing.T) {
    host:="search.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","plain","timeout_tls",5000)
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","tlsrec-split","ok",350)
        }
    }
    if !siteSearchCommit(inst,host,"tlsrec-split",gen) {t.Fatal("3/3 exact-host validated candidate not applied")}
    if got:=zapret2Auto.choose(host);got!="tlsrec-split" {
        t.Fatalf("verified method unavailable to next TCP connection: %s",got)
    }
    if got:=zapret2Auto.choose("unrelated.example.org");got!="split-1" {
        t.Fatalf("site-scoped evidence leaked: %s",got)
    }
    if siteSearchCommit(inst,host,"auto",gen) || siteSearchCommit(inst,host,"plain",gen) {
        t.Fatal("auto/plain cannot be promoted as method")
    }
}
func TestSiteSearchRejectsIntermittentAndDuplicateSamples(t *testing.T) {
    host:="search.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","plain","timeout_tls",5000)
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","split","ok",400)
        }
    }
    // A single failed repeat on any selected address invalidates promotion.
    siteSearchState.Lock()
    siteSearchState.current.trials["1|h1|split"].good[1]=false
    siteSearchState.Unlock()
    if siteSearchCommit(inst,host,"split",gen) {t.Fatal("2/3 incorrectly promoted")}
    siteSearchRecord(inst,host,gen,1,2,"h1","split","ok",100) // duplicate cannot heal
    if siteSearchCommit(inst,host,"split",gen) {t.Fatal("replayed sample healed failure")}
    // Even a full candidate is not enough when untouched TCP works 2/3.
    siteSearchState.Lock()
    siteSearchState.current.trials["1|h1|split"].good[1]=true
    siteSearchState.current.trials["0|h1|plain"].good[0]=true
    siteSearchState.current.trials["0|h1|plain"].good[1]=true
    siteSearchState.Unlock()
    if siteSearchCommit(inst,host,"split",gen) {t.Fatal("not better than intermittent baseline")}
    if siteSearchCommit(inst,host,"split",gen+1) {t.Fatal("stale generation accepted")}
}
func TestSiteSearchExpiredRunNeverPromotesOrChangesAUTO(t *testing.T) {
    host:="search.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1"})
    siteSearchState.Lock()
    siteSearchState.current.prepared=time.Now().Add(-siteSearchTTL)
    siteSearchState.Unlock()
    for i:=1;i<=3;i++ {
        siteSearchRecord(inst,host,gen,0,i,"h1","plain","timeout_tls",5000)
        siteSearchRecord(inst,host,gen,0,i,"h1","fake-5","ok",300)
    }
    if siteSearchCommit(inst,host,"fake-5",gen) {
        t.Fatal("expired DNS address set promoted")
    }
    if got:=zapret2Auto.choose(host);got!="split-1" {t.Fatal(got)}
}

func TestSiteSearchRestoresPlainBaselineWhenStable(t *testing.T) {
    host:="www.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    // Simulate a stale prior workaround without disabling existing streams.
    zapret2Auto.mu.Lock()
    zapret2Auto.entries[host]=&adaptiveEntry{preferred:"fake-5"}
    zapret2Auto.mu.Unlock()
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","plain","ok",500)
        }
    }
    if !siteSearchCommit(inst,host,"plain",gen) {
        t.Fatal("verified original TLS/HTTP was not selected")
    }
    if got:=zapret2Auto.choose(host);got!="pass" {
        t.Fatalf("AUTO failed to restore original unmodified TCP, got %s",got)
    }
}

func TestSiteSearchVerifiedBackupUsedOnlyAfterTimeoutBreaker(t *testing.T) {
    host:="www.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","plain","timeout_tls",6000)
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","tlsrec-split","ok",900)
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","fake-5","ok",1100)
            siteSearchRecord(inst,host,gen,ip,attempt,"h1","split","timeout_tls",6000)
        }
    }
    if !siteSearchCommit(inst,host,"tlsrec-split",gen) {t.Fatal("primary not applied")}
    zapret2Auto.mu.Lock()
    fallback:=zapret2Auto.entries[host].verifiedFallback
    zapret2Auto.mu.Unlock()
    if fallback!="fake-5" {t.Fatalf("unexpected fallback %s",fallback)}
    if got:=zapret2Auto.choose(host);got!="tlsrec-split" {t.Fatal(got)}
    for i:=0;i<adaptiveStallThreshold;i++ {
        zapret2Auto.observeStallTracked(host,"tlsrec-split",gen)
    }
    if got:=zapret2Auto.choose(host);got!="fake-5" {
        t.Fatalf("verified backup not activated after breaker: %s",got)
    }
    zapret2Auto.mu.Lock()
    remaining:=zapret2Auto.entries[host].verifiedFallback
    zapret2Auto.mu.Unlock()
    if remaining!="" {t.Fatalf("backup must be consumed: %s",remaining)}
    if got:=zapret2Auto.choose("other.example.org");got!="split-1" {
        t.Fatalf("backup leaked to another hostname: %s",got)
    }
}
func TestSiteSearchNeverUsesUnverifiedBackup(t *testing.T) {
    host:="www.example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1"})
    for attempt:=1;attempt<=3;attempt++ {
        siteSearchRecord(inst,host,gen,0,attempt,"h1","plain","timeout_tls",6000)
        siteSearchRecord(inst,host,gen,0,attempt,"h1","tlsrec-split","ok",900)
        siteSearchRecord(inst,host,gen,0,attempt,"h1","fake-5","timeout_tls",6000)
    }
    if !siteSearchCommit(inst,host,"tlsrec-split",gen) {t.Fatal("primary not applied")}
    zapret2Auto.mu.Lock()
    fallback:=zapret2Auto.entries[host].verifiedFallback
    zapret2Auto.mu.Unlock()
    if fallback!="" {t.Fatalf("unverified backup selected: %s",fallback)}
}

func TestSiteSearchServiceTargetsUseRealResourceNotMissingRoot(t *testing.T) {
    image:=siteSearchHTTPTarget("i.ytimg.com")
    if image.host!="i.ytimg.com" || image.path!="/vi/jNQXAC9IVRw/hqdefault.jpg" ||
        image.contentKind!="jpeg" || !image.ipv4Only {
        t.Fatalf("thumbnail must use fixed public JPEG, got %#v",image)
    }
    validJPEG:=append([]byte{0xff,0xd8,0xff},make([]byte,253)...)
    if got:=classifyProbeHTTP(200,"image/jpeg",validJPEG,nil,image);got!="ok" {
        t.Fatalf("valid thumbnail must verify content, got %s",got)
    }
    if got:=classifyProbeHTTP(404,"text/html",[]byte("not found"),nil,image);got=="ok" {
        t.Fatal("404 root falsely verified as thumbnail JPEG")
    }
    api:=siteSearchHTTPTarget("youtubei.googleapis.com")
    if api.path!="/youtubei/v1/browse" || api.contentKind!="http_transport" ||
        !api.ipv4Only {t.Fatalf("API is not a bounded transport-only test: %#v",api)}
    if got:=classifyProbeHTTP(403,"application/json",[]byte("{}"),nil,api);got!="http_reachable" {
        t.Fatalf("authenticated API failure must be transport only, got %s",got)
    }
    generic:=siteSearchHTTPTarget("example.org")
    if generic.path!="/" || generic.contentKind!="site_http" ||
        generic.host!="example.org" {t.Fatalf("generic domain request changed: %#v",generic)}
}

func TestSiteSearchHTTPTransportOnlyDoesNotAutoPromote(t *testing.T) {
    host:="example.org"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1"})
    for attempt:=1;attempt<=3;attempt++ {
        siteSearchRecord(inst,host,gen,0,attempt,"h1","plain","redirect",260)
        siteSearchRecord(inst,host,gen,0,attempt,"h1","tlsrec-split","http_reachable",280)
    }
    if siteSearchCommit(inst,host,"plain",gen) ||
        siteSearchCommit(inst,host,"tlsrec-split",gen) {
        t.Fatal("3xx/4xx HTTP reachability must not be promoted as 2xx content")
    }
}
