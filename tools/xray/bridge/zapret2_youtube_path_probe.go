//go:build linux

package bridge

// Optional multi-service YouTube verification through the SAME protected
// Xray test outbounds as the site strategy search. Fixed, public, anonymous
// homepage/API/thumbnail endpoints only; no user tokens, media manifests,
// video URLs, cookies, redirect following, OS DNS or global VPN changes.
import (
    "context"
    "net"
    "strings"
    "sync"
    "time"

    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
)

type youtubePathSpec struct {
    host string
    path string
    kind string
}
var youtubePathTargets=map[string]youtubePathSpec{
    "home":{"www.youtube.com","/","html"},
    // Anonymous fixed POST. A 4xx establishes only HTTP/2 transport.
    "api":{"youtubei.googleapis.com","/youtubei/v1/browse","api_browse"},
    // Thumbnail JPEG is an independent static-media CDN control, not a video.
    "thumb":{"i.ytimg.com","/vi/jNQXAC9IVRw/hqdefault.jpg","jpeg"},
}
var youtubePathState=struct{
    sync.Mutex
    instance *core.Instance
    generation uint64
    started time.Time
    answers map[string]fixedDoHAnswer
}{}

func parseYoutubePathTarget(id string) (string,string,bool,bool) {
    if !strings.HasPrefix(id,"yt_path_") {return "","",false,false}
    rest:=strings.TrimPrefix(id,"yt_path_")
    for name:=range youtubePathTargets {
        if rest=="prepare_"+name {return name,"",true,true}
        if rest==name+"_h1" {return name,"h1",false,true}
        if rest==name+"_h2" {return name,"h2",false,true}
    }
    return "","",false,false
}
func youtubePathPrepare(ctx context.Context,inst *core.Instance,generation uint64,
    id string) Zapret2HTTPSResult {
    result:=Zapret2HTTPSResult{Outcome:"doh_invalid",DnsFingerprint:"-",
        Protocol:"dns",TLSStage:"none",ALPN:"-"}
    target:=youtubePathTargets[id]
    answer:=resolveOptInSiteDoH(ctx,inst,target.host)
    if answer.status!="ok" {
        result.Outcome=answer.status
        result.HTTPStatus=answer.httpStatus
        return result
    }
    ips:=make([]string,0,len(answer.ips))
    for _,ip:=range answer.ips {if sitePublicIPv4(ip){ips=append(ips,ip)}}
    if len(ips)==0 {result.Outcome="doh_no_ipv4";return result}
    answer.ips=ips
    youtubePathState.Lock()
    if youtubePathState.instance!=inst || youtubePathState.generation!=generation ||
        time.Since(youtubePathState.started)>=siteSearchTTL {
        youtubePathState.answers=make(map[string]fixedDoHAnswer)
        youtubePathState.started=time.Now()
    }
    youtubePathState.instance=inst
    youtubePathState.generation=generation
    youtubePathState.answers[id]=answer
    youtubePathState.Unlock()
    result.Outcome="dns_ready"
    result.HTTPStatus=answer.httpStatus
    result.DnsFingerprint=answer.fingerprint
    result.DnsAnswers=len(ips)
    return result
}
func youtubePathPrepared(inst *core.Instance,generation uint64,id string)(fixedDoHAnswer,bool) {
    youtubePathState.Lock()
    defer youtubePathState.Unlock()
    a,ok:=youtubePathState.answers[id]
    if !ok || youtubePathState.instance!=inst ||
        youtubePathState.generation!=generation ||
        time.Since(youtubePathState.started)>=siteSearchTTL {
        return fixedDoHAnswer{},false
    }
    a.ips=append([]string(nil),a.ips...)
    return a,true
}
func probeYoutubePath(strategy,id string,timeout time.Duration) Zapret2HTTPSResult {
    started:=time.Now()
    out:=Zapret2HTTPSResult{Outcome:"invalid_target",DnsFingerprint:"-",
        Protocol:"dns",TLSStage:"none",ALPN:"-"}
    done:=func(r Zapret2HTTPSResult)Zapret2HTTPSResult{r.Elapsed=time.Since(started);return r}
    name,protocol,prepare,ok:=parseYoutubePathTarget(id)
    if !ok {return done(out)}
    tag,valid:=zapret2TestStrategies[strategy]
    if !valid || strategy=="auto" {out.Outcome="invalid_strategy";return done(out)}
    if prepare && strategy!="plain" {out.Outcome="invalid_strategy";return done(out)}
    if timeout<time.Second || timeout>15*time.Second {out.Outcome="invalid_timeout";return done(out)}
    mu.Lock()
    inst:=current
    mu.Unlock()
    if inst==nil {out.Outcome="engine_off";return done(out)}
    generation:=zapret2Auto.generationSnapshot()
    ctx,cancel:=context.WithTimeout(context.Background(),timeout)
    defer cancel()
    if prepare {return done(youtubePathPrepare(ctx,inst,generation,name))}
    answer,available:=youtubePathPrepared(inst,generation,name)
    if !available {out.Outcome="dns_not_prepared";return done(out)}
    out.DnsFingerprint=answer.fingerprint
    out.DnsAnswers=len(answer.ips)
    out.Protocol=protocol
    out.IPIndex=0
    if len(answer.ips)==0 {out.Outcome="doh_no_ipv4";return done(out)}
    // All strategies for a given service use the SAME sorted first public
    // A record during one scan. Never infer video success from thumbnails.
    dest:=xnet.Destination{Network:xnet.Network_TCP,
        Address:xnet.ParseAddress(answer.ips[0]),Port:443}
    conn,err:=core.Dial(session.SetForcedOutboundTagToContext(ctx,tag+"-ipv4"),inst,dest)
    if err!=nil {
        out.Outcome="dial_failed"
        if ctx.Err()!=nil {out.Outcome="timeout_dial"}
        return done(out)
    }
    defer conn.Close()
    closed:=make(chan struct{})
    defer close(closed)
    go func(){select{case <-ctx.Done():_ = conn.Close();case <-closed:}}()
    spec:=youtubePathTargets[name]
    target:=zapret2TestTarget{host:spec.host,path:spec.path,
        contentKind:spec.kind,ipv4Only:true}
    return done(matrixWithMetadata(matrixHTTP(ctx,conn,target,protocol),out))
}

// The report never receives an IP, a credential, a raw URL with user input,
// a server response body, a QUIC CID or a TLS certificate.
var _ net.Conn
