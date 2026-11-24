//go:build linux && (!localdpi_native || !cgo)

package zapret2

func encodeTLSRecordSplit(first []byte, recordLen, split int) ([]byte, int, bool) {
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

func localNativePlan(_, _ string) bool { return false }
