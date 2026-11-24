//go:build linux && (!localdpi_native || !cgo)

package zapret2

import (
    "path/filepath"
    "testing"
)

func TestDefaultTLSPlanStillUsesSelectedAlpine(t *testing.T) {
    previous:=PlannerSocket()
    t.Cleanup(func(){_ = SetPlannerSocket(previous)})
    if err:=SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    if _,err:=PlanFor(TagPrefix+"tlsrec-split","tcp",tlsClientHelloFixture(t,"example.test"));err==nil {
        t.Fatal("ordinary build unexpectedly switched planner")
    }
    if n,f:=NativeTLSRecordStats();n!=0 || f!=0 {t.Fatal("native counters in default build")}
}
