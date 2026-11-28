//go:build linux

package bridge

import (
    "testing"
    "time"
)

func newProbeAdaptiveSelector() *adaptiveSelector {
    return newAdaptiveSelector(socketCapabilities)
}

func TestSiteObservationsDoNotPublishBeforeExplicitCommit(t *testing.T) {
    const host="www.youtube.com"
    inst,g:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            recordSiteSearchTestSample(inst,host,g,ip,attempt,"h1","plain","timeout_tls",8000)
            recordSiteSearchTestSample(inst,host,g,ip,attempt,"h1","tlsrec-split","ok",1000)
        }
    }
    zapret2Auto.mu.Lock()
    entry:=zapret2Auto.entries[host]
    zapret2Auto.mu.Unlock()
    if entry!=nil {t.Fatal("diagnostic observations published without commit")}
    if !commitSiteSearchTestRun(inst,host,"tlsrec-split",g) {t.Fatal("explicit verified commit rejected")}
    if got:=zapret2Auto.choose(host);got!="tlsrec-split" {t.Fatal("verified preference unavailable",got)}
    for _,other:=range []string{"youtube.com","i.ytimg.com","r1.googlevideo.com","youtubei.googleapis.com"} {
        if got:=zapret2Auto.choose(other);got!="split-1" {t.Fatal("verified preference escaped host",other,got)}
    }
}

func TestVerifiedPreferenceRetainsShortResponsesAndIndependentHealth(t *testing.T) {
    a:=newProbeAdaptiveSelector()
    const host="www.youtube.com"
    e:=a.entryLocked(host)
    e.cooldown=map[string]time.Time{"tlsrec-split":time.Now().Add(time.Hour),"split":time.Now().Add(time.Hour)}
    e.stalls=map[string]int{"tlsrec-split":1,"split":1}
    e.installVerifiedPreference("tlsrec-split","fake-5")
    if _,ok:=e.cooldown["tlsrec-split"];ok {t.Fatal("winner cooldown retained")}
    if e.stalls["tlsrec-split"]!=0 || e.stalls["split"]!=1 || !time.Now().Before(e.cooldown["split"]) {
        t.Fatal("verified preference changed unrelated method health")
    }
    for _,bytes:=range []int64{8192,8192,adaptivePayloadThreshold,8192,8192} {
        a.observe(host,"tlsrec-split",bytes)
        if e.preferred!="tlsrec-split" || !e.probeSeeded || e.weakFailures!=0 {
            t.Fatal("verified preference lost on successful short response")
        }
    }
    a.observe(host,"tlsrec-split",0)
    if e.preferred!="tlsrec-split" {t.Fatal("one weak observation retired preference")}
    a.observe(host,"tlsrec-split",0)
    if e.preferred!="" || e.verifiedFallback!="" || e.probeSeeded {t.Fatal("retired preference retained evidence")}
}
