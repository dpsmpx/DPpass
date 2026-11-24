//go:build linux

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi"

// Compatibility delegate for the portable reference encoder.
func encodeTLSRecordSplitGo(first []byte, recordLen, split int) ([]byte,int,bool) {
    return localdpi.EncodeTLSRecordSplit(first,recordLen,split)
}
