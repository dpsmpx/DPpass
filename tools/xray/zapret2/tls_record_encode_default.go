//go:build linux && (!localdpi_native || !cgo)

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi"

func encodeTLSRecordSplit(first []byte, recordLen, split int, _ bool) ([]byte, int, bool) {
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

func localNativePlan(_, _ string) bool { return false }

func encodeHTTPHostNameCase(first []byte, _ bool) ([]byte,bool) {
    return localdpi.HTTPHostNameCase(first)
}
