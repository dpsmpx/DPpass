//go:build linux

package zapret2

// encodeTLSRecordSplitGo is the established portable reference encoder.
func encodeTLSRecordSplitGo(first []byte, recordLen, split int) ([]byte, int, bool) {
    rewritten := make([]byte, 0, len(first)+5)
    rewritten = append(rewritten, first[:3]...)
    rewritten = append(rewritten, byte(split>>8), byte(split))
    rewritten = append(rewritten, first[5:5+split]...)
    firstRecordEnd := len(rewritten)
    secondLen := recordLen - split
    rewritten = append(rewritten, first[:3]...)
    rewritten = append(rewritten, byte(secondLen>>8), byte(secondLen))
    rewritten = append(rewritten, first[5+split:5+recordLen]...)
    rewritten = append(rewritten, first[5+recordLen:]...)
    return rewritten, firstRecordEnd, true
}
