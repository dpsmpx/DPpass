//go:build linux && localdpi_native && cgo

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi/native"

// Only an explicit experimental build tag enables this implementation.
// Selection stays in the shared Go planner. Oversize/unsupported input
// retains the established portable implementation.
func encodeTLSRecordSplit(first []byte, recordLen, split int, diagnostic bool) ([]byte, int, bool) {
    // Only diagnostic calls request independent name-parser agreement.
    // SNI-less records retain the existing encoder path. A disagreement
    // uses the already validated portable encoder, never new native offsets.
    if diagnostic {
        if _,_,ok:=SNIRange(first);ok && !native.TLSNameAgrees(first) {
            recordNativeTLSPlan(diagnostic,false)
            return encodeTLSRecordSplitGo(first,recordLen,split)
        }
    }
    if b,ok:=native.SplitTLSRecord(first,split);ok {
        recordNativeTLSPlan(diagnostic,true)
        return b,5+split,true
    }
    recordNativeTLSPlan(diagnostic,false)
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

// Only the explicitly tagged experiment dispatches the existing TLS method
// locally even when an Alpine planner is selected. No other method changes.
func localNativePlan(tag,network string) bool {
    return network=="tcp" && tag==TagPrefix+"tlsrec-split"
}
