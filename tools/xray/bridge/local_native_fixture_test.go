//go:build linux && localdpi_native && cgo

package bridge

import (
    "path/filepath"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestTaggedLocalHTTPFixtureUsesNativeWithSelectedPlanner(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    before,skipped:=DesyncStats()
    result:=ProbeZapret2HTTPS("http-hostcase","local_http_hostcase",5*time.Second)
    if result.Outcome!="local_http_verified" || result.AppliedDelta!=1 || result.SkippedDelta!=0 {
        t.Fatal("native HTTP loopback fixture failed",result)
    }
    if r:=ProbeZapret2HTTPS("http-hostows","local_http_hostcase",5*time.Second);r.Outcome=="local_http_verified" {
        t.Fatal("unavailable selected planner silently replaced")
    }
    after,afterSkipped:=DesyncStats()
    if before!=after || skipped!=afterSkipped {t.Fatal("diagnostic modified live counters")}
}
