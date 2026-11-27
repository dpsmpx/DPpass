//go:build linux

package bridge

import (
    "testing"
    "time"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestLocalHTTPDiagnosticThroughNativeEntry(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    before,skips:=DesyncStats()
    for _,method:=range []string{"plain","http-hostcase","http-hostows"} {
        result:=ProbeZapret2HTTPS(method,"local_http_hostcase",5*time.Second)
        want:=int64(0)
        if method!="plain" {want=1}
        if result.Outcome!="local_http_verified" || result.AppliedDelta!=want ||
            result.SkippedDelta!=0 || result.HTTPStatus!=0 || result.BodyBytes!=0 {
            t.Fatalf("unexpected loopback result: %+v",result)
        }
    }
    after,afterSkips:=DesyncStats()
    if after!=before || afterSkips!=skips {t.Fatal("diagnostic changed live counters")}
}

func TestLocalHTTPDiagnosticRejectsOtherMethodsAndRemoteTarget(t *testing.T) {
    for _,method:=range []string{"auto","split","fake-5","http-hostcase "} {
        if result:=ProbeZapret2HTTPS(method,"local_http_hostcase",time.Second);result.Outcome!="invalid_strategy" {
            t.Fatal(method,result)
        }
    }
    for _,timeout:=range []time.Duration{0,6*time.Second} {
        if result:=ProbeZapret2HTTPS("plain","local_http_hostcase",timeout);result.Outcome!="invalid_timeout" {
            t.Fatal(result)
        }
    }
    for _,method:=range []string{"http-hostcase","http-hostows"} {
        if result:=ProbeZapret2HTTPS(method,"google_final",time.Second);result.Outcome!="invalid_strategy" {
            t.Fatal("HTTP rewrite admitted to HTTPS",result)
        }
    }
}
