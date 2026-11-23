//go:build linux

package bridge

import (
    "testing"
    "time"

    "github.com/xtls/xray-core/core"
)

func TestYoutubePathSuiteOnlyAcceptsFixedAnonymousEndpoints(t *testing.T) {
    for _,name:=range []string{"home","api","thumb"} {
        if _,ok:=youtubePathTargets[name];!ok {t.Fatal(name)}
        for _,mode:=range []string{"h1","h2"} {
            id,proto,prep,ok:=parseYoutubePathTarget("yt_path_"+name+"_"+mode)
            if !ok || id!=name || proto!=mode || prep {t.Fatalf("invalid target %s",id)}
        }
        id,proto,prep,ok:=parseYoutubePathTarget("yt_path_prepare_"+name)
        if !ok || id!=name || proto!="" || !prep {t.Fatalf("invalid preparation %s",id)}
    }
    for _,id:=range []string{
        "yt_path_api_h3","yt_path_api_secret_h2","yt_path_home_h1:/foo",
        "yt_path_prepare_evil","yt_path_googlevideo_h1",
        "yt_path_api_h2_cookie","yt_path_home_http",
        "yt_path_api_http://example.org","yt_path_thumb_h2/123",
    }{
        if _,_,_,ok:=parseYoutubePathTarget(id);ok {t.Fatalf("unapproved target %s",id)}
    }
    if youtubePathTargets["api"].kind!="api_browse" ||
        youtubePathTargets["api"].path!="/youtubei/v1/browse" {
        t.Fatal("fixed anonymous API contract changed")
    }
    if got:=classifyProbeHTTP(403,"application/json",nil,nil,
        zapret2TestTarget{contentKind:"api_browse"});got!="http_reachable" {
        t.Fatalf("anonymous API rejection was wrongly treated as site success: %s",got)
    }
    if got:=classifyProbeHTTP(200,"application/json",nil,nil,
        zapret2TestTarget{contentKind:"api_browse"});got=="ok" {
        t.Fatal("anonymous API status alone was treated as working feed")
    }
}
func TestYoutubePathPreparedBoundToNetworkAndExpiry(t *testing.T) {
    inst:=&core.Instance{}
    youtubePathState.Lock()
    youtubePathState.instance=inst
    youtubePathState.generation=9
    youtubePathState.started=time.Now()
    youtubePathState.answers=map[string]fixedDoHAnswer{
        "home":{status:"ok",ips:[]string{"1.1.1.1"}},
    }
    youtubePathState.Unlock()
    t.Cleanup(func(){youtubePathState.Lock();youtubePathState.answers=nil;youtubePathState.Unlock()})
    if _,ok:=youtubePathPrepared(inst,9,"home");!ok {t.Fatal("good same-network probe not prepared")}
    if _,ok:=youtubePathPrepared(inst,10,"home");ok {t.Fatal("stale network probe accepted")}
    if _,ok:=youtubePathPrepared(inst,9,"api");ok {t.Fatal("non-prepared CDN/API reused homepage")}
    youtubePathState.Lock()
    youtubePathState.started=time.Now().Add(-siteSearchTTL)
    youtubePathState.Unlock()
    if _,ok:=youtubePathPrepared(inst,9,"home");ok {t.Fatal("expired address set used")}
}
