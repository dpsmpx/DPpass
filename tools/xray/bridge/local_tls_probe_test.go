//go:build linux

package bridge

import (
    "path/filepath"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestLocalTLSNativeEntryMatrix(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket("");err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    before,skips:=DesyncStats()
    for _,target:=range []string{"local_tls12","local_tls13"} {
        for _,method:=range []string{"plain","multisplit","tlsrec-split","tlsrec-chain"} {
            t.Run(target+"/"+method,func(t *testing.T){
                result:=ProbeZapret2HTTPS(method,target,5*time.Second)
                expected:=int64(1)
                if method=="plain" {expected=0}
                if result.Outcome!="local_tls_verified" || result.AppliedDelta!=expected ||
                    result.SkippedDelta!=0 || result.HTTPStatus!=0 || result.BodyBytes!=0 ||
                    result.DnsFingerprint!="" || result.Protocol!="" {
                    t.Fatalf("unexpected TLS result: %+v",result)
                }
            })
        }
    }
    after,afterSkips:=DesyncStats()
    if before!=after || skips!=afterSkips {t.Fatal("changed live counters")}
}

func TestLocalTLSRejectsInvalidAdmission(t *testing.T) {
    for _,method:=range []string{"auto","fake-5","http-hostcase","http-hostows","split"} {
        if r:=ProbeZapret2HTTPS(method,"local_tls13",time.Second);r.Outcome!="invalid_strategy" {t.Fatal(method,r)}
    }
    for _,timeout:=range []time.Duration{0,6*time.Second} {
        if r:=ProbeZapret2HTTPS("plain","local_tls13",timeout);r.Outcome!="invalid_timeout" {t.Fatal(r)}
    }
    if r:=probeLocalTLS("plain","remote",time.Second);r.Outcome!="invalid_target" {t.Fatal(r)}
}

func TestLocalTLSDoesNotFallbackWhenSelectedPlannerUnavailable(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    if r:=ProbeZapret2HTTPS("plain","local_tls13",5*time.Second);r.Outcome!="local_tls_verified" {t.Fatal(r)}
    if r:=ProbeZapret2HTTPS("tlsrec-chain","local_tls13",5*time.Second);r.Outcome=="local_tls_verified" {
        t.Fatal("chain bypassed unavailable selected planner")
    }
    // multisplit always uses the selected external planner, including native-tag builds.
    if r:=ProbeZapret2HTTPS("multisplit","local_tls13",5*time.Second);r.Outcome=="local_tls_verified" {
        t.Fatal("unavailable selected planner reported success")
    }
}
