//go:build linux && localdpi_native && cgo

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi/native"

// Only an explicit experimental build tag enables this implementation.
// Selection stays in the shared Go planner. Oversize/unsupported input
// retains the established portable implementation.
func encodeTLSRecordSplit(first []byte, recordLen, split int) ([]byte, int, bool) {
    if b,ok:=native.SplitTLSRecord(first,split);ok {
        nativeTLSRecords.Add(1)
        return b,5+split,true
    }
    nativeTLSFallbacks.Add(1)
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

// Only the explicitly tagged experiment dispatches the existing TLS method
// locally even when an Alpine planner is selected. No other method changes.
func localNativePlan(tag,network string) bool {
    return network=="tcp" && tag==TagPrefix+"tlsrec-split"
}
