package localdpi

import "encoding/binary"

// CompleteTLSClientHelloRecordLen checks only the record/message lengths
// required by the established encoder, not the whole TLS handshake syntax.
// The record may be followed by additional bytes, which must be preserved.
func CompleteTLSClientHelloRecordLen(first []byte) (int,bool) {
    if !IsTLSClientHelloPrefix(first) {return 0,false}
    recordLen:=int(binary.BigEndian.Uint16(first[3:5]))
    if recordLen<12 || recordLen>16384 || recordLen>len(first)-5 {return 0,false}
    helloLen:=int(first[6])<<16|int(first[7])<<8|int(first[8])
    if helloLen==0 || helloLen>recordLen-4 {return 0,false}
    return recordLen,true
}

// EncodeTLSRecordSplit is the existing portable reference implementation.
// Its inputs are validated before slicing, even for standalone callers.
// It returns a newly owned buffer and never modifies first.
func EncodeTLSRecordSplit(first []byte, recordLen, split int) ([]byte,int,bool) {
    actual,ok:=CompleteTLSClientHelloRecordLen(first)
    if !ok || actual!=recordLen || split<=4 || split>=recordLen {return nil,0,false}
    rewritten:=make([]byte,0,len(first)+5)
    rewritten=append(rewritten,first[:3]...)
    rewritten=append(rewritten,byte(split>>8),byte(split))
    rewritten=append(rewritten,first[5:5+split]...)
    firstRecordEnd:=len(rewritten)
    secondLen:=recordLen-split
    rewritten=append(rewritten,first[:3]...)
    rewritten=append(rewritten,byte(secondLen>>8),byte(secondLen))
    rewritten=append(rewritten,first[5+split:5+recordLen]...)
    rewritten=append(rewritten,first[5+recordLen:]...)
    return rewritten,firstRecordEnd,true
}

// EncodeTLSRecordChain creates three records from a complete first record.
// Positions are payload offsets, not packet offsets. Trailing bytes are
// preserved; no input aliases the result.
func EncodeTLSRecordChain(first []byte, a,b int) ([]byte,int,int,bool) {
    n,ok:=CompleteTLSClientHelloRecordLen(first)
    if !ok || a<=4 || b<=a || b>=n {return nil,0,0,false}
    out:=make([]byte,0,len(first)+10)
    prev:=0
    for _,end:=range []int{a,b,n} {
        size:=end-prev
        out=append(out,first[:3]...)
        out=append(out,byte(size>>8),byte(size))
        out=append(out,first[5+prev:5+end]...)
        prev=end
    }
    out=append(out,first[5+n:]...)
    return out,5+a,10+b,true
}
