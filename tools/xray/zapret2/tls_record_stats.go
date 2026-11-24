//go:build linux

package zapret2

import "sync/atomic"

var nativeTLSRecords atomic.Int64
var nativeTLSFallbacks atomic.Int64

// NativeTLSRecordStats counts generated plans, not successful sends or
// verified content. Process-wide, no destinations or payloads retained.
func NativeTLSRecordStats() (encoded,referenceFallback int64) {
    return nativeTLSRecords.Load(),nativeTLSFallbacks.Load()
}
