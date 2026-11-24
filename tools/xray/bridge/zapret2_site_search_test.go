//go:build linux

package bridge

import (
    "context"
    "fmt"
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

func TestAPISweepEightIPv4H1H2GrammarAndIsolation(t *testing.T) {
    for _,mode:=range []struct{prefix,kind string}{
        {"site_sweep_h1_ip","sweep_h1"},
        {"site_sweep_h2_ip","sweep_h2"},
    } {
        for ip:=0;ip<siteSweepMaxIPs;ip++ {
            for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
                target:=fmt.Sprintf("%s%02d_a%d_:youtubei.googleapis.com",
                    mode.prefix,ip,attempt)
                r,ok:=parseSiteSearchRequest(target)
                if !ok || r.kind!=mode.kind || r.index!=ip ||
                    r.attempt!=attempt || r.host!="youtubei.googleapis.com" {
                    t.Fatalf("unexpected API sweep parse: %s %#v %t",target,r,ok)
                }
                if r.kind=="http" || r.kind=="quic" {
                    t.Fatal("sweep must not enter siteSearchRecord / AUTO evidence")
                }
            }
        }
    }
    for _,target:=range []string{
        "site_sweep_h1_ip08_a1_:youtubei.googleapis.com",
        "site_sweep_h2_ip99_a1_:youtubei.googleapis.com",
        "site_sweep_h2_ip07_a4_:youtubei.googleapis.com",
        "site_sweep_h2_ip07_a0_:youtubei.googleapis.com",
        "site_sweep_h2_ip00_a1_:www.youtube.com",
        "site_sweep_h1_ip00_a1_:example.org",
        "site_sweep_h1_ip00_a1_:127.0.0.1",
        "site_sweep_h1_ip00_a1_:youtubei.googleapis.com/path",
        "site_ip02_a1_:youtubei.googleapis.com", // original AUTO search stays capped at 2
    } {
        if _,ok:=parseSiteSearchRequest(target);ok {
            t.Fatalf("unsafe or out-of-scope target allowed: %s",target)
        }
    }
}

func TestAPISweepTransportResultsDoNotProvideAUTOCandidate(t *testing.T) {
    host:="youtubei.googleapis.com"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    // Unlike site_ipXX, the site_sweep request type does NOT record any
    // of these diagnostics. Even completed H2 transport cannot be an
    // input to native site_apply for an H1 strategy.
    r,ok:=parseSiteSearchRequest("site_sweep_h2_ip01_a1_:"+host)
    if !ok || r.kind!="sweep_h2" {t.Fatalf("bad sweep request: %#v",r)}
    if siteSearchCommit(inst,host,"tlsrec-split",gen) ||
        siteSearchCommit(inst,host,"plain",gen) {
        t.Fatal("diagnostic-only sweep must never promote missing 3/3 H1 evidence")
    }
}

func TestSameIPGoogleSNIControlGrammarAndNoAutoTraining(t *testing.T) {
    host:="youtubei.googleapis.com"
    for index:=0;index<siteSweepMaxIPs;index++ {
        for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
            id:=fmt.Sprintf("site_sni_google_ip%02d_a%d_:%s",index,attempt,host)
            request,ok:=parseSiteSearchRequest(id)
            if !ok||request.kind!="sni_control"||
                request.host!=host||request.index!=index||request.attempt!=attempt {
                t.Fatalf("bad same-IP control: %q %#v %t",id,request,ok)
            }
        }
    }
    for _,id:=range []string{
        "site_sni_google_ip08_a1_:youtubei.googleapis.com",
        "site_sni_google_ip99_a1_:youtubei.googleapis.com",
        "site_sni_google_ip00_a0_:youtubei.googleapis.com",
        "site_sni_google_ip00_a4_:youtubei.googleapis.com",
        "site_sni_google_ip00_a1_:www.youtube.com",
        "site_sni_google_ip00_a1_:www.google.com",
        "site_sni_google_ip00_a1_:localhost",
        "site_sni_google_ip00_a1_:youtubei.googleapis.com/path",
    } {
        if _,ok:=parseSiteSearchRequest(id);ok {
            t.Fatalf("unsafe SNI comparator target accepted: %q",id)
        }
    }
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    if siteSearchCommit(inst,host,"tlsrec-split",gen) ||
        siteSearchCommit(inst,host,"plain",gen) {
        t.Fatal("SNI comparator must not contribute any site_apply evidence")
    }
}

func TestSiteSearchMayRecordOnlyRegularOptimizerTrials(t *testing.T) {
    for _,kind:=range []string{"http","quic"} {
        if !siteSearchMayRecord(kind) {
            t.Fatalf("real optimizer sample kind rejected: %s",kind)
        }
    }
    for _,kind:=range []string{
        "sweep_h1","sweep_h2","sni_control","site_prepare","site_apply","",
    } {
        if siteSearchMayRecord(kind) {
            t.Fatalf("diagnostic data could leak into AUTO: %s",kind)
        }
    }
}

func TestYouTubeAPITLSVersionControlGrammarAndNoAUTO(t *testing.T) {
    host:="youtubei.googleapis.com"
    for _,version:=range []string{"12","13"} {
        for _,sni:=range []string{"api","google"} {
            for ip:=0;ip<siteSearchMaxIPs;ip++ {
                for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
                    kind:="tls"+version+"_"+sni
                    id:=fmt.Sprintf("site_%s_ip%02d_a%d_:%s",kind,ip,attempt,host)
                    r,ok:=parseSiteSearchRequest(id)
                    if !ok || r.kind!=kind || r.host!=host ||
                        r.index!=ip || r.attempt!=attempt {
                        t.Fatalf("invalid accepted version probe: %s %#v %t",id,r,ok)
                    }
                    if siteSearchMayRecord(r.kind) {
                        t.Fatalf("version diagnostic must not change AUTO: %s",id)
                    }
                }
            }
        }
    }
    for _,id:=range []string{
        "site_tls12_api_ip02_a1_:youtubei.googleapis.com",
        "site_tls13_google_ip08_a1_:youtubei.googleapis.com",
        "site_tls12_google_ip00_a0_:youtubei.googleapis.com",
        "site_tls13_api_ip01_a4_:youtubei.googleapis.com",
        "site_tls12_api_ip00_a1_:www.youtube.com",
        "site_tls13_google_ip00_a1_:www.google.com",
        "site_tls11_api_ip00_a1_:youtubei.googleapis.com",
        "site_tls12_api_ip00_a1_:youtubei.googleapis.com/x",
    } {
        if _,ok:=parseSiteSearchRequest(id);ok {
            t.Fatalf("unsafe version probe accepted: %q",id)
        }
    }
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    if siteSearchCommit(inst,host,"plain",gen) ||
        siteSearchCommit(inst,host,"tlsrec-split",gen) {
        t.Fatal("version-only diagnostics must not produce site apply evidence")
    }
}

func TestHTTPVersionProbeRejectsUnknownTLSVersion(t *testing.T) {
    target:=zapret2TestTarget{
        host:"youtubei.googleapis.com",path:"/youtubei/v1/browse",
        contentKind:"http_transport",ipv4Only:true,
    }
    result:=matrixHTTPWithVersion(context.Background(),nil,target,"h1",0x0101)
    if result.Outcome!="invalid_tls_version" {
        t.Fatalf("unexpected invalid-version result: %q",result.Outcome)
    }
}

func TestDPTSPublicTargetsAreStrictAndNeverAUTO(t *testing.T) {
    for _,k:=range []string{
        "h1","h2","t12","t13","gh1","gh2","g12","g13",
        "q1","q2","h3","h3api",
    } {
        for ip:=0;ip<siteSweepMaxIPs;ip++ {
            for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
                id:=fmt.Sprintf("dpts_%s_ip%02d_a%d_:youtubei.googleapis.com",
                    k,ip,attempt)
                req,ok:=parseSiteSearchRequest(id)
                if !ok || req.kind!="script_"+k || req.index!=ip ||
                    req.attempt!=attempt || req.host!="youtubei.googleapis.com" {
                    t.Fatalf("bad DPTS grammar %s: %#v %t",id,req,ok)
                }
                if siteSearchMayRecord(req.kind) {
                    t.Fatalf("script trial can poison AUTO: %q",id)
                }
            }
        }
    }
    for _,id:=range []string{
        "dpts_h1_ip08_a1_:router.local",
        "dpts_h1_ip08_a1_:127.0.0.1",
        "dpts_h1_ip08_a1_:www.google.com:22",
        "dpts_h1_ip08_a1_:youtubei.googleapis.com",
        "dpts_h1_ip00_a0_:youtubei.googleapis.com",
        "dpts_h1_ip00_a4_:youtubei.googleapis.com",
        "dpts_h1_ip00_a1_:youtubei.googleapis.com/path",
        "dpts_h1_ip00_a1_:youtubei.googleapis.com?token=secret",
        "dpts_arbitrary_ip00_a1_:youtubei.googleapis.com",
    } {
        if _,ok:=parseSiteSearchRequest(id);ok {
            t.Fatalf("unsafe DPTS target accepted: %q",id)
        }
    }
    r,ok:=parseSiteSearchRequest("dpts_train:youtubei.googleapis.com")
    if !ok||r.kind!="script_train" {t.Fatalf("neural train grammar: %#v",r)}
    if siteSearchMayRecord(r.kind) {t.Fatal("training result can poison AUTO")}
}

func TestDPTSTrainingRequiresFullContentAndPlainBaselineFailure(t *testing.T) {
    host:="www.youtube.com"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    if code:=siteScriptTrain(inst,host,"tlsrec-split",gen);
        code!="neural_no_evidence" {
        t.Fatalf("empty evidence must reject training: %s",code)
    }
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
            siteScriptRecord(inst,host,gen,ip,attempt,"plain","timeout_tls_no_reply",5000)
            siteScriptRecord(inst,host,gen,ip,attempt,"tlsrec-split","http_reachable",100)
        }
    }
    if code:=siteScriptTrain(inst,host,"tlsrec-split",gen);
        code!="neural_no_evidence" {
        t.Fatalf("HTTP transport alone must reject training: %s",code)
    }
    // A duplicate HTTP sample must not overwrite a recorded result.
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
            siteScriptRecord(inst,host,gen,ip,attempt,"tlsrec-split","ok",100)
        }
    }
    if code:=siteScriptTrain(inst,host,"tlsrec-split",gen);
        code!="neural_no_evidence" {
        t.Fatalf("duplicate samples must not promote success: %s",code)
    }
    if code:=siteScriptTrain(inst,host,"plain",gen);code!="invalid_strategy" {
        t.Fatalf("plain is not a neural output class: %s",code)
    }
    if siteSearchCommit(inst,host,"tlsrec-split",gen) {
        t.Fatal("even full script batches never satisfy the regular AUTO gate")
    }
}

func TestDPTSVerifiedThreeOfThreeTrainsLocalMLPOnceWithoutAuto(t *testing.T) {
    defer func(){ _=ConfigureZapret2NeuralModel(nil) }()
    if err:=ConfigureZapret2NeuralModel(generatedTestModel(t,32));err!=nil {
        t.Fatal(err)
    }
    host:="www.youtube.com"
    inst,gen:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=siteSearchAttempts;attempt++ {
            siteScriptRecord(inst,host,gen,ip,attempt,
                "plain","timeout_tls_no_reply",5000)
            siteScriptRecord(inst,host,gen,ip,attempt,
                "tlsrec-split","ok",400)
        }
    }
    zapret2Neural.mu.Lock()
    before,_:=nnForward(zapret2Neural.weights,host,5,false)
    zapret2Neural.mu.Unlock()
    if result:=siteScriptTrain(inst,host,"tlsrec-split",gen);
        result!="neural_trained" {
        t.Fatalf("complete content evidence did not teach: %s",result)
    }
    zapret2Neural.mu.Lock()
    after,_:=nnForward(zapret2Neural.weights,host,5,false)
    zapret2Neural.mu.Unlock()
    if after<=before {t.Fatal("verified learning did not raise candidate weight")}
    if result:=siteScriptTrain(inst,host,"tlsrec-split",gen);
        result!="neural_already_trained" {
        t.Fatalf("duplicate training accepted: %s",result)
    }
    if siteSearchCommit(inst,host,"tlsrec-split",gen) {
        t.Fatal("script-trained model must not commit live AUTO")
    }
}
