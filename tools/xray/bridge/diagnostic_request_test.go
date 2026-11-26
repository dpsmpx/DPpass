//go:build linux

package bridge

import (
    "context"
    "sync"
    "testing"
    "time"

    "github.com/xtls/xray-core/common/session"
)

func TestDiagnosticRequestContextIsolationAndFinalization(t *testing.T) {
    first,a:=newDiagnosticRequestContext(context.Background())
    second,b:=newDiagnosticRequestContext(context.Background())
    nested,cancel:=context.WithTimeout(session.SetForcedOutboundTagToContext(first,"dppass:test-split"),time.Second)
    defer cancel()
    if diagnosticRequestFromContext(nested)!=a || diagnosticRequestFromContext(second)!=b ||
        diagnosticRequestFromContext(context.Background())!=nil || a==b {
        t.Fatal("request ownership not preserved")
    }
    var wg sync.WaitGroup
    for i:=0;i<50;i++ {
        wg.Add(2)
        go func(){defer wg.Done();a.record(true)}()
        go func(){defer wg.Done();b.record(false)}()
    }
    wg.Wait()
    if applied,skipped:=a.finish();applied!=50 || skipped!=0 {t.Fatal("first request counts",applied,skipped)}
    a.record(false)
    b.record(true)
    if applied,skipped:=a.finish();applied!=50 || skipped!=0 {t.Fatal("finished request changed",applied,skipped)}
    if applied,skipped:=b.finish();applied!=1 || skipped!=50 {t.Fatal("second request counts",applied,skipped)}
    var missing *diagnosticRequestCounters
    missing.record(true)
    if applied,skipped:=missing.finish();applied!=0 || skipped!=0 {t.Fatal("unbound event acquired attribution")}
}
