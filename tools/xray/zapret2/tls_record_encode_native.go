//go:build linux && localdpi_native && cgo

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi/native"

// Only an explicit experimental build tag enables this implementation.
// Selection stays in the shared Go planner. Oversize/unsupported input
// retains the established portable implementation.
func encodeTLSRecordSplit(first []byte, recordLen, split int) ([]byte, int, bool) {
    if b,ok:=native.SplitTLSRecord(first,split);ok {
        return b,5+split,true
    }
    return encodeTLSRecordSplitGo(first,recordLen,split)
}
