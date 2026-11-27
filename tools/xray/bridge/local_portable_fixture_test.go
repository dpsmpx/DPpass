//go:build linux && (!localdpi_native || !cgo)

package bridge

import (
    "path/filepath"
    "testing"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestLocalPortableHTTPFixtureDoesNotFallbackFromSelectedPlanner(t *testing.T) {
    prev:=zapret2.PlannerSocket()
    if err:=zapret2.SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    t.Cleanup(func(){_ = zapret2.SetPlannerSocket(prev)})
    if r:=ProbeZapret2HTTPS("http-hostcase","local_http_hostcase",5*time.Second);r.Outcome=="local_http_verified" {
        t.Fatal("portable build bypassed unavailable selected daemon")
    }
}
