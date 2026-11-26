//go:build linux

package zapret2

import "sync/atomic"

var nativeTLSRecords atomic.Int64
var nativeTLSFallbacks atomic.Int64
var diagnosticNativeTLSRecords atomic.Int64
var diagnosticNativeTLSFallbacks atomic.Int64

func recordNativeTLSPlan(diagnostic,encoded bool) {
    if diagnostic {
        if encoded {diagnosticNativeTLSRecords.Add(1)} else {diagnosticNativeTLSFallbacks.Add(1)}
    } else {
        if encoded {nativeTLSRecords.Add(1)} else {nativeTLSFallbacks.Add(1)}
    }
}

func diagnosticNativeTLSRecordStats() (int64,int64) {
    return diagnosticNativeTLSRecords.Load(),diagnosticNativeTLSFallbacks.Load()
}

// NativeTLSRecordStats counts generated plans, not successful sends or
// verified content. Process-wide, no destinations or payloads retained.
func NativeTLSRecordStats() (encoded,referenceFallback int64) {
    return nativeTLSRecords.Load(),nativeTLSFallbacks.Load()
}
