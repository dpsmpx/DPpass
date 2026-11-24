//go:build linux

package bridge

// Explicit, bounded any-public-host strategy explorer. It never changes
// Xray routing, DNS policy, current connections, or VPN subscription servers.
// DNS is certificate-verified Google DoH on a fixed protected IP, and each
// candidate uses a pinned public IPv4 through the existing private test tag.
// Only the authenticated host name is used for TLS SNI and HTTP Host.
import (
    "context"
    "crypto/sha256"
    "encoding/hex"
    "net"
    "strconv"
    "strings"
    "sync"
    "time"

    quic "github.com/apernet/quic-go"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
)

const siteSearchTTL = 5 * time.Minute
const siteSearchMaxIPs = 2
const siteSearchAttempts = 3

// Exact finite set of methods exposed by the private Android outbounds.
// fake modes already combine a TTL-limited fake with the real TCP split;
// tlsrec-split combines lossless TLS-record and TCP fragmentation.
var siteSearchMethods = [...]string{
    "plain", "split-1", "split", "tlsrec-split", "fake-3", "fake-5", "disorder",
}
var siteSearchQUICMethods = [...]string{"plain", "fake-3", "fake-5"}

type siteSearchRequest struct {
    kind string
    host string
    index int
    attempt int
}
func validOptInSiteHost(host string) bool {
    if len(host)<4 || len(host)>253 || strings.ToLower(host)!=host ||
        strings.ContainsAny(host, ":/@\\%?# \t\r\n") ||
        net.ParseIP(host)!=nil {return false}
    labels:=strings.Split(host,".")
    if len(labels)<2 {return false}
    suffix:=labels[len(labels)-1]
    for _,label:=range labels {
        if len(label)<1 || len(label)>63 {return false}
        for i:=0;i<len(label);i++ {
            c:=label[i]
            if !(c>='a' && c<='z' || c>='0' && c<='9' ||
                c=='-' && i>0 && i<len(label)-1) {return false}
        }
    }
    if len(suffix)<2 {return false}
    // IDN.toASCII outputs a valid punycode TLD containing hyphens and
    // digits. Permit only its xn-- form, never a numeric-looking TLD.
    if strings.HasPrefix(suffix,"xn--") {
        if len(suffix)<6 {return false}
    } else {
        for _,c:=range suffix {if c<'a'||c>'z' {return false}}
    }
    switch suffix {
    case "local","localhost","internal","lan","home","test","invalid","example","onion","arpa":
        return false
    }
    // Refuse service-discovery/local domains and DNS rebinding targets.
    if strings.HasSuffix(host,".home.arpa") {return false}
    return true
}

// An IP appearing in a public DoH answer is not necessarily publicly
// routable. Exclude RFC1918, CGNAT, TEST-NET, documentation, loopback,
// link-local, benchmarking and IANA-reserved prefixes before ANY core.Dial.
func sitePublicIPv4(s string) bool {
    ip:=net.ParseIP(s).To4()
    if ip==nil || !ip.IsGlobalUnicast() || ip.IsPrivate() {return false}
    a,b,c:=ip[0],ip[1],ip[2]
    if a==0 || a==10 || a==127 || a>=224 ||
        a==100 && b>=64 && b<=127 ||
        a==169 && b==254 ||
        a==172 && b>=16 && b<=31 ||
        a==192 && (b==0 || b==168) ||
        a==198 && (b==18 || b==19 || b==51 && c==100) ||
        a==203 && b==0 && c==113 {return false}
    return true
}

func parseSiteSearchRequest(target string) (siteSearchRequest,bool) {
    kind,host,ok:=strings.Cut(target,":")
    if !ok || !validOptInSiteHost(host) {return siteSearchRequest{},false}
    r:=siteSearchRequest{kind:kind,host:host}
    if kind=="site_prepare"||kind=="site_apply" {return r,true}
    var prefix string
    switch {
    case strings.HasPrefix(kind,"site_ip"):prefix="site_ip"
    case strings.HasPrefix(kind,"site_quic_ip"):prefix="site_quic_ip"
    default:return siteSearchRequest{},false
    }
    rest:=strings.TrimPrefix(kind,prefix)
    if len(rest)!=6 || rest[2:4]!="_a" || rest[4]<'1'||rest[4]>'3' || rest[5]!='_' {
        // Canonical fixed identifier: site_ip00_a1_ or site_quic_ip00_a1_
        return siteSearchRequest{},false
    }
    index,err:=strconv.Atoi(rest[:2])
    if err!=nil || index<0 || index>=siteSearchMaxIPs {return siteSearchRequest{},false}
    r.index=index
    r.attempt=int(rest[4]-'0')
    if prefix=="site_ip" {r.kind="http"} else {r.kind="quic"}
    return r,true
}

type siteSearchTrial struct {
    received [siteSearchAttempts]bool
    good [siteSearchAttempts]bool
    elapsed [siteSearchAttempts]int64
}
type siteSearchRun struct {
    instance *core.Instance
    generation uint64
    host string
    prepared time.Time
    answer fixedDoHAnswer
    trials map[string]*siteSearchTrial
}
var siteSearchState=struct {
    sync.Mutex
    current *siteSearchRun
}{}

func siteSearchReady(inst *core.Instance, host string, gen uint64) (*siteSearchRun,bool) {
    siteSearchState.Lock()
    defer siteSearchState.Unlock()
    r:=siteSearchState.current
    if r==nil || r.instance!=inst || r.generation!=gen || r.host!=host ||
        time.Since(r.prepared)>=siteSearchTTL || len(r.answer.ips)==0 {return nil,false}
    // Clone only immutable address strings and basic metadata; no mutable
    // evidence can leave the lock. It never includes private addresses.
    copied:=*r
    copied.answer.ips=append([]string(nil),r.answer.ips...)
    copied.trials=nil
    return &copied,true
}
func siteSearchRecord(inst *core.Instance, host string, gen uint64,
    index,attempt int, proto,strategy string, outcome string, elapsed int64) {
    siteSearchState.Lock()
    defer siteSearchState.Unlock()
    r:=siteSearchState.current
    if r==nil || r.instance!=inst || r.generation!=gen || r.host!=host ||
        time.Since(r.prepared)>=siteSearchTTL {return}
    key:=strconv.Itoa(index)+"|"+proto+"|"+strategy
    if r.trials==nil {r.trials=make(map[string]*siteSearchTrial)}
    trial:=r.trials[key]
    if trial==nil {trial=&siteSearchTrial{};r.trials[key]=trial}
    slot:=attempt-1
    if slot<0||slot>=siteSearchAttempts||trial.received[slot] {return}
    trial.received[slot]=true
    trial.good[slot]=(outcome=="ok" && proto=="h1" ||
        outcome=="quic_verified" && proto=="quic")
    trial.elapsed[slot]=elapsed
}

func siteSearchTrialGood(r *siteSearchRun,index int,proto,strategy string) (int,bool,int64) {
    t:=r.trials[strconv.Itoa(index)+"|"+proto+"|"+strategy]
    if t==nil {return 0,false,0}
    success:=0
    var duration int64
    for i:=0;i<siteSearchAttempts;i++ {
        if !t.received[i] {return success,false,0}
        if t.good[i] {success++;duration+=t.elapsed[i]}
    }
    return success,true,duration
}
func siteSearchCommit(inst *core.Instance,host,method string,gen uint64) bool {
    if method=="auto" {return false}
    recognized:=method=="plain"
    for _,m:=range siteSearchMethods {if method==m {recognized=true}}
    if !recognized {return false}

    siteSearchState.Lock()
    r:=siteSearchState.current
    if r==nil||r.instance!=inst||r.generation!=gen||r.host!=host||
        time.Since(r.prepared)>=siteSearchTTL {siteSearchState.Unlock();return false}
    count:=len(r.answer.ips)
    if count>siteSearchMaxIPs {count=siteSearchMaxIPs}
    // The native engine independently verifies the entire requested
    // candidate and baseline on every selected IP. Incomplete/duplicate
    // samples or intermittent 1/3 or 2/3 do not permit auto-promotion.
    for i:=0;i<count;i++ {
        baseline,baseComplete,_:=siteSearchTrialGood(r,i,"h1","plain")
        winner,complete,_:=siteSearchTrialGood(r,i,"h1",method)
        goodBaseline:=method=="plain" && baseComplete && baseline==3
        goodBetterMethod:=method!="plain" && baseComplete && complete &&
            baseline<=1 && winner==3
        if !goodBaseline && !goodBetterMethod {
            siteSearchState.Unlock()
            return false
        }
    }
    // A backup is only eligible if it independently passed all three
    // HTTPS checks at every identical pinned IPv4. Rank by average
    // successful latency; never reuse a QUIC-only or incomplete profile.
    backup:=""
    bestMillis:=int64(1<<62)
    if method!="plain" {
        for _,other:=range siteSearchMethods {
            if other=="plain"||other==method {continue}
            var total int64
            stable:=true
            for i:=0;i<count;i++ {
                successes,complete,elapsed:=siteSearchTrialGood(r,i,"h1",other)
                if !complete||successes!=siteSearchAttempts {stable=false;break}
                total+=elapsed
            }
            if stable && total<bestMillis {
                backup=other
                bestMillis=total
            }
        }
    }
    siteSearchState.Unlock()
    zapret2Auto.mu.Lock()
    defer zapret2Auto.mu.Unlock()
    if zapret2Auto.generation!=gen {return false}
    if zapret2Auto.entries==nil {zapret2Auto.entries=make(map[string]*adaptiveEntry)}
    if len(zapret2Auto.entries)>=adaptiveMaxHosts {zapret2Auto.entries=make(map[string]*adaptiveEntry)}
    entry:=zapret2Auto.entries[host]
    if entry==nil {entry=&adaptiveEntry{};zapret2Auto.entries[host]=entry}
    selected:=method
    if selected=="plain" {selected="pass"}
    entry.preferred=selected
    entry.verifiedFallback=backup
    entry.probeSeeded=method!="plain"
    entry.weakFailures=0
    entry.smallResponses=nil
    // Any existing timeout suspension for this exact, freshly proven
    // candidate is cleared; unrelated host/method health is untouched.
    if entry.cooldown!=nil {delete(entry.cooldown,selected)}
    if entry.stalls!=nil {delete(entry.stalls,selected)}
    return true
}

// Fixed public resource probes prevent false negative GET / responses on
// media CDNs. The API test is deliberately transport-only: unauthenticated
// GET cannot prove a YouTube app browse/feed API POST.
func siteSearchHTTPTarget(host string) zapret2TestTarget {
    switch host {
    case "i.ytimg.com":
        target:=zapret2TestTargets["youtube_thumbnail"]
        target.ipv4Only=true
        return target
    case "youtubei.googleapis.com":
        return zapret2TestTargets["youtube_api_ipv4"]
    default:
        return zapret2TestTarget{host:host,path:"/",
            contentKind:"site_http",ipv4Only:true}
    }
}

func probeSiteSearchHTTPS(strategy,targetID string,timeout time.Duration) Zapret2HTTPSResult {
    started:=time.Now()
    result:=Zapret2HTTPSResult{Outcome:"invalid_target",DnsFingerprint:"-",
        Protocol:"dns",TLSStage:"none",ALPN:"-"}
    finish:=func(r Zapret2HTTPSResult) Zapret2HTTPSResult {
        r.Elapsed=time.Since(started)
        return r
    }
    request,ok:=parseSiteSearchRequest(targetID)
    if !ok {return finish(result)}
    tag,valid:=zapret2TestStrategies[strategy]
    if !valid || strategy=="auto" {result.Outcome="invalid_strategy";return finish(result)}
    if timeout<time.Second||timeout>15*time.Second {
        result.Outcome="invalid_timeout";return finish(result)
    }
    mu.Lock()
    inst:=current
    mu.Unlock()
    if inst==nil {result.Outcome="engine_off";return finish(result)}
    gen:=zapret2Auto.generationSnapshot()
    ctx,cancel:=context.WithTimeout(context.Background(),timeout)
    defer cancel()

    if request.kind=="site_prepare" {
        if strategy!="plain" {result.Outcome="invalid_strategy";return finish(result)}
        // Preparing a new host invalidates all previous samples; nothing
        // is learned until a fully completed explicit commit.
        siteSearchState.Lock()
        siteSearchState.current=nil
        siteSearchState.Unlock()
        answer:=resolveOptInSiteDoH(ctx,inst,request.host)
        result.Outcome=answer.status
        result.HTTPStatus=answer.httpStatus
        if answer.status!="ok" {return finish(result)}
        public:=make([]string,0,len(answer.ips))
        for _,ip:=range answer.ips {
            if sitePublicIPv4(ip) {public=append(public,ip)}
        }
        if len(public)==0 {result.Outcome="doh_no_ipv4";return finish(result)}
        answer.ips=public
        // Fingerprint exactly the filtered, sorted A set that will be
        // dialed. Never reveal or hash private/special-use answer records
        // into a misleading address-set identifier.
        digest:=sha256.Sum256([]byte(strings.Join(public,",")))
        answer.fingerprint=hex.EncodeToString(digest[:4])
        // This is not an arbitrary Android-resolver fallback.
        result.Outcome="dns_ready"
        result.DnsFingerprint=answer.fingerprint
        result.DnsAnswers=len(public)
        siteSearchState.Lock()
        siteSearchState.current=&siteSearchRun{instance:inst,generation:gen,
            host:request.host,prepared:time.Now(),answer:answer,
            trials:make(map[string]*siteSearchTrial)}
        siteSearchState.Unlock()
        return finish(result)
    }
    preparedRun,ready:=siteSearchReady(inst,request.host,gen)
    if !ready {result.Outcome="dns_not_prepared";return finish(result)}
    result.DnsFingerprint=preparedRun.answer.fingerprint
    result.DnsAnswers=len(preparedRun.answer.ips)
    if request.kind=="site_apply" {
        if siteSearchCommit(inst,request.host,strategy,gen) {
            result.Outcome="auto_applied"
        }else{result.Outcome="auto_no_winner"}
        return finish(result)
    }
    if request.index>=len(preparedRun.answer.ips) {
        result.Outcome="invalid_index";return finish(result)
    }
    allowed:=false
    if request.kind=="http" {
        for _,m:=range siteSearchMethods {if m==strategy {allowed=true}}
        result.Protocol="h1"
    } else if request.kind=="quic" {
        for _,m:=range siteSearchQUICMethods {if m==strategy {allowed=true}}
        result.Protocol="quic"
    }
    if !allowed {result.Outcome="invalid_strategy";return finish(result)}
    result.IPIndex=request.index
    ip:=preparedRun.answer.ips[request.index] // public only; never sent in report
    network:=xnet.Network_TCP
    if request.kind=="quic" {network=xnet.Network_UDP}
    dest:=xnet.Destination{Network:network,
        Address:xnet.ParseAddress(ip),Port:443}
    conn,err:=core.Dial(session.SetForcedOutboundTagToContext(ctx,tag+"-ipv4"),inst,dest)
    if err!=nil {
        result.Outcome="dial_failed"
        if ctx.Err()!=nil {result.Outcome="timeout_dial"}
        siteSearchRecord(inst,request.host,gen,request.index,request.attempt,
            result.Protocol,strategy,result.Outcome,0)
        return finish(result)
    }
    defer conn.Close()
    done:=make(chan struct{})
    defer close(done)
    go func(){select {case <-ctx.Done():_=conn.Close();case <-done:}}()
    // A root URL is not a valid resource on every HTTPS service:
    // i.ytimg.com GET / normally replies 404; google.com may return 301.
    // Reuse the pinned public thumbnail from the existing fixed target
    // catalog, and the unauthenticated transport-only YouTube API path.
    // Never pass arbitrary user-controlled paths, credentials or cookies.
    target:=siteSearchHTTPTarget(request.host)
    var checked Zapret2HTTPSResult
    if request.kind=="quic" {
        checked=matrixQUIC(ctx,conn,ip,request.host,quic.Version1)
    }else{
        checked=matrixHTTP(ctx,conn,target,"h1")
    }
    checked=matrixWithMetadata(checked,result)
    checked.Elapsed=time.Since(started)
    // QUIC TLS is a transport diagnostic only. This never auto-pins an
    // IP shared between unrelated hosts; only 3/3 HTTP evidence can
    // teach the exact-host TCP AUTO selector by explicit apply.
    siteSearchRecord(inst,request.host,gen,request.index,request.attempt,
        result.Protocol,strategy,checked.Outcome,checked.Elapsed.Milliseconds())
    return finish(checked)
}
