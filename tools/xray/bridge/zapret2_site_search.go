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
const siteSweepMaxIPs = 8 // isolated diagnostic, NEVER eligible for AUTO commit
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
    if kind=="dpts_train" {r.kind="script_train";return r,true}
    var prefix string
    switch {
    case strings.HasPrefix(kind,"dpts_h1_ip"):
        prefix="dpts_h1_ip";r.kind="script_h1"
    case strings.HasPrefix(kind,"dpts_h2_ip"):
        prefix="dpts_h2_ip";r.kind="script_h2"
    case strings.HasPrefix(kind,"dpts_t12_ip"):
        prefix="dpts_t12_ip";r.kind="script_t12"
    case strings.HasPrefix(kind,"dpts_t13_ip"):
        prefix="dpts_t13_ip";r.kind="script_t13"
    case strings.HasPrefix(kind,"dpts_g12_ip"):
        prefix="dpts_g12_ip";r.kind="script_g12"
    case strings.HasPrefix(kind,"dpts_g13_ip"):
        prefix="dpts_g13_ip";r.kind="script_g13"
    case strings.HasPrefix(kind,"dpts_gh1_ip"):
        prefix="dpts_gh1_ip";r.kind="script_gh1"
    case strings.HasPrefix(kind,"dpts_gh2_ip"):
        prefix="dpts_gh2_ip";r.kind="script_gh2"
    case strings.HasPrefix(kind,"dpts_q1_ip"):
        prefix="dpts_q1_ip";r.kind="script_q1"
    case strings.HasPrefix(kind,"dpts_q2_ip"):
        prefix="dpts_q2_ip";r.kind="script_q2"
    case strings.HasPrefix(kind,"dpts_h3_ip"):
        prefix="dpts_h3_ip";r.kind="script_h3"
    case strings.HasPrefix(kind,"dpts_h3api_ip"):
        prefix="dpts_h3api_ip";r.kind="script_h3api"
    case strings.HasPrefix(kind,"site_tls12_api_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_tls12_api_ip"
        r.kind="tls12_api"
    case strings.HasPrefix(kind,"site_tls13_api_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_tls13_api_ip"
        r.kind="tls13_api"
    case strings.HasPrefix(kind,"site_tls12_google_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_tls12_google_ip"
        r.kind="tls12_google"
    case strings.HasPrefix(kind,"site_tls13_google_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_tls13_google_ip"
        r.kind="tls13_google"
    case strings.HasPrefix(kind,"site_sni_google_ip"):
        // Exact same pinned API IPv4, but an independent, public control
        // name. This is certificate-verified; no domain fronting or
        // upstream destination rewrite for production connections.
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_sni_google_ip"
        r.kind="sni_control"
    case strings.HasPrefix(kind,"site_sweep_h1_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_sweep_h1_ip"
        r.kind="sweep_h1"
    case strings.HasPrefix(kind,"site_sweep_h2_ip"):
        if host!="youtubei.googleapis.com" {return siteSearchRequest{},false}
        prefix="site_sweep_h2_ip"
        r.kind="sweep_h2"
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
    limit:=siteSearchMaxIPs
    if r.kind=="sweep_h1" || r.kind=="sweep_h2" ||
        r.kind=="sni_control" || strings.HasPrefix(r.kind,"script_") {
        limit=siteSweepMaxIPs
    }
    if err!=nil || index<0 || index>=limit {return siteSearchRequest{},false}
    r.index=index
    r.attempt=int(rest[4]-'0')
    if prefix=="site_ip" {r.kind="http"} else if prefix=="site_quic_ip" {r.kind="quic"}
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
    // Distinct per-run evidence: script samples must NEVER satisfy site_apply.
    scriptTrials map[string]*siteSearchTrial
    scriptTrained map[string]bool
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
// Shared admission guard: diagnostic H1/H2 and same-IP SNI controls
// are never samples for the strict 3/3 native AUTO selection.
func siteSearchMayRecord(kind string) bool {
    return kind=="http" || kind=="quic"
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

// The script evidence store is independent of the normal site_apply store.
// A malicious or incomplete pasted script therefore cannot commit AUTO.
func siteScriptRecord(inst *core.Instance,host string,gen uint64,
    index,attempt int,strategy,outcome string,elapsed int64) {
    siteSearchState.Lock()
    defer siteSearchState.Unlock()
    r:=siteSearchState.current
    if r==nil || r.instance!=inst || r.generation!=gen || r.host!=host ||
        time.Since(r.prepared)>=siteSearchTTL {return}
    if index<0||index>=len(r.answer.ips)||attempt<1||attempt>siteSearchAttempts {return}
    key:=strconv.Itoa(index)+"|"+strategy
    trial:=r.scriptTrials[key]
    if trial==nil {trial=&siteSearchTrial{};r.scriptTrials[key]=trial}
    slot:=attempt-1
    if trial.received[slot] {return}
    trial.received[slot]=true
    trial.good[slot]=outcome=="ok"
    trial.elapsed[slot]=elapsed
}

func scriptEvidence(r *siteSearchRun,index int,strategy string) (int,bool) {
    t:=r.scriptTrials[strconv.Itoa(index)+"|"+strategy]
    if t==nil {return 0,false}
    success:=0
    for k:=0;k<siteSearchAttempts;k++ {
        if !t.received[k] {return 0,false}
        if t.good[k] {success++}
    }
    return success,true
}

// User must explicitly request neural=verified. A single TLS handshake,
// HTTP 4xx, 2/3, CDN transport-only reply or simulated outcome is never
// sufficient. A non-plain candidate must pass content validation on every
// selected IP while the plain baseline fails on the SAME IPs.
func siteScriptTrain(inst *core.Instance,host,strategy string,gen uint64) string {
    if strategy=="plain" || nnCandidateIndex(strategy,false)<0 {
        return "invalid_strategy"
    }
    siteSearchState.Lock()
    r:=siteSearchState.current
    if r==nil || r.instance!=inst || r.generation!=gen || r.host!=host ||
        time.Since(r.prepared)>=siteSearchTTL {
        siteSearchState.Unlock()
        return "dns_not_prepared"
    }
    if r.scriptTrained[strategy] {
        siteSearchState.Unlock()
        return "neural_already_trained"
    }
    count:=len(r.answer.ips)
    if count>siteSearchMaxIPs {count=siteSearchMaxIPs}
    if count==0 {
        siteSearchState.Unlock()
        return "neural_no_evidence"
    }
    for ip:=0;ip<count;ip++ {
        baseline,baselineDone:=scriptEvidence(r,ip,"plain")
        winner,winnerDone:=scriptEvidence(r,ip,strategy)
        if !baselineDone || !winnerDone ||
            baseline!=0 || winner!=siteSearchAttempts {
            siteSearchState.Unlock()
            return "neural_no_evidence"
        }
    }
    // Prevent duplicate commits in the same prepared-network generation.
    r.scriptTrained[strategy]=true
    siteSearchState.Unlock()
    if !zapret2Neural.learnVerifiedDiagnostic(host,strategy) {
        // Missing weights must not be represented as a successful update.
        siteSearchState.Lock()
        if siteSearchState.current==r {delete(r.scriptTrained,strategy)}
        siteSearchState.Unlock()
        return "neural_unavailable"
    }
    return "neural_trained"
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
            trials:make(map[string]*siteSearchTrial),
            scriptTrials:make(map[string]*siteSearchTrial),
            scriptTrained:make(map[string]bool)}
        siteSearchState.Unlock()
        return finish(result)
    }
    preparedRun,ready:=siteSearchReady(inst,request.host,gen)
    if !ready {result.Outcome="dns_not_prepared";return finish(result)}
    result.DnsFingerprint=preparedRun.answer.fingerprint
    result.DnsAnswers=len(preparedRun.answer.ips)
    if request.kind=="script_train" {
        result.Outcome=siteScriptTrain(inst,request.host,strategy,gen)
        return finish(result)
    }
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
    if strings.HasPrefix(request.kind,"script_") {
        // Execute only compiled, bounded and pinned DPTS primitives.
        // Every method must exist as an actual registered protected outbound.
        switch request.kind {
        case "script_h1","script_h2","script_t12","script_t13",
             "script_g12","script_g13","script_gh1","script_gh2":
            for _,m:=range siteSearchMethods {if m==strategy {allowed=true}}
            if request.kind=="script_h2" || request.kind=="script_gh2" {
                result.Protocol="h2"
            } else {result.Protocol="h1"}
        case "script_q1","script_q2","script_h3","script_h3api":
            for _,m:=range siteSearchQUICMethods {if m==strategy {allowed=true}}
            result.Protocol="quic"
            if request.kind=="script_q2" {result.Protocol="quicv2"}
            if request.kind=="script_h3" {result.Protocol="h3"}
            if request.kind=="script_h3api" {result.Protocol="h3api"}
            if request.kind=="script_h3" || request.kind=="script_h3api" {
                if request.host!="youtubei.googleapis.com" {allowed=false}
            }
        }
    } else if request.kind=="http" {
        for _,m:=range siteSearchMethods {if m==strategy {allowed=true}}
        result.Protocol="h1"
    } else if request.kind=="quic" {
        for _,m:=range siteSearchQUICMethods {if m==strategy {allowed=true}}
        result.Protocol="quic"
    } else if request.kind=="tls12_api" || request.kind=="tls13_api" ||
        request.kind=="tls12_google" || request.kind=="tls13_google" {
        // Only plain is admitted: TLS version is the ONLY new variable.
        // This is diagnostic-only and excludes any native AUTO recording.
        allowed=strategy=="plain"
        result.Protocol="h1"
    } else if request.kind=="sni_control" {
        // The SNI/Host control tests Google on the identical API IP
        // and rejects every non-plain profile to avoid confounding.
        allowed=strategy=="plain"
        result.Protocol="h1"
    } else if request.kind=="sweep_h1" || request.kind=="sweep_h2" {
        // Only three existing implemented profiles, only the known API
        // host, and only explicitly prepared public Google DoH IPv4.
        // The sweep is diagnostic: no evidence reaches siteSearchRecord.
        allowed=strategy=="plain" || strategy=="tlsrec-split" || strategy=="fake-5"
        if request.kind=="sweep_h1" {result.Protocol="h1"} else {result.Protocol="h2"}
    }
    if !allowed {result.Outcome="invalid_strategy";return finish(result)}
    result.IPIndex=request.index
    ip:=preparedRun.answer.ips[request.index] // public only; never sent in report
    network:=xnet.Network_TCP
    if request.kind=="quic" || request.kind=="script_q1" ||
        request.kind=="script_q2" || request.kind=="script_h3" ||
        request.kind=="script_h3api" {network=xnet.Network_UDP}
    dest:=xnet.Destination{Network:network,
        Address:xnet.ParseAddress(ip),Port:443}
    conn,err:=core.Dial(session.SetForcedOutboundTagToContext(ctx,tag+"-ipv4"),inst,dest)
    if err!=nil {
        result.Outcome="dial_failed"
        if ctx.Err()!=nil {result.Outcome="timeout_dial"}
        if siteSearchMayRecord(request.kind) {
            siteSearchRecord(inst,request.host,gen,request.index,request.attempt,
                result.Protocol,strategy,result.Outcome,0)
        }
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
    if request.kind=="sni_control" || request.kind=="tls12_google" ||
        request.kind=="tls13_google" || request.kind=="script_gh1" ||
        request.kind=="script_gh2" || request.kind=="script_g12" ||
        request.kind=="script_g13" {
        target=zapret2TestTarget{host:"www.google.com",path:"/",
            contentKind:"http_transport",ipv4Only:true}
    }
    var checked Zapret2HTTPSResult
    if request.kind=="quic" {
        checked=matrixQUIC(ctx,conn,ip,request.host,quic.Version1)
    }else if request.kind=="script_q1" {
        checked=matrixQUIC(ctx,conn,ip,request.host,quic.Version1)
    }else if request.kind=="script_q2" {
        checked=matrixQUIC(ctx,conn,ip,request.host,quic.Version2)
    }else if request.kind=="script_h3" || request.kind=="script_h3api" {
        mode:="h3"
        if request.kind=="script_h3api" {mode="h3api"}
        checked=matrixH3Pinned(ctx,conn,ip,request.host,mode)
    }else if request.kind=="script_t12" || request.kind=="script_g12" {
        checked=matrixHTTPWithVersion(ctx,conn,target,"h1",0x0303)
    }else if request.kind=="script_t13" || request.kind=="script_g13" {
        checked=matrixHTTPWithVersion(ctx,conn,target,"h1",0x0304)
    }else if request.kind=="tls12_api" || request.kind=="tls12_google" {
        checked=matrixHTTPWithVersion(ctx,conn,target,"h1",0x0303) // TLS 1.2
    }else if request.kind=="tls13_api" || request.kind=="tls13_google" {
        checked=matrixHTTPWithVersion(ctx,conn,target,"h1",0x0304) // TLS 1.3
    }else{
        checked=matrixHTTP(ctx,conn,target,result.Protocol)
    }
    checked=matrixWithMetadata(checked,result)
    checked.Elapsed=time.Since(started)
    if request.kind=="script_h1" {
        siteScriptRecord(inst,request.host,gen,request.index,request.attempt,
            strategy,checked.Outcome,checked.Elapsed.Milliseconds())
    }
    // QUIC TLS is a transport diagnostic only. This never auto-pins an
    // IP shared between unrelated hosts; only 3/3 HTTP evidence can
    // teach the exact-host TCP AUTO selector by explicit apply.
    if siteSearchMayRecord(request.kind) {
        siteSearchRecord(inst,request.host,gen,request.index,request.attempt,
            result.Protocol,strategy,checked.Outcome,checked.Elapsed.Milliseconds())
    }
    // Sweep samples cannot modify the trusted AUTO 3/3 evidence even if
    // all eight IPs happen to reply. They only return redacted stages.
    return finish(checked)
}
