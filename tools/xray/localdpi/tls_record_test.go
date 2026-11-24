package localdpi

import (
    "bytes"
    "encoding/binary"
    "testing"
)

func TestPortableTLSRecordEncoderSharedContract(t *testing.T) {
    for _,size:=range []int{12,64,512,16384} {
        first:=make([]byte,5+size+6)
        copy(first,[]byte{22,3,3,0,0,1,0,0,0})
        binary.BigEndian.PutUint16(first[3:5],uint16(size))
        hello:=size-4
        first[6],first[7],first[8]=byte(hello>>16),byte(hello>>8),byte(hello)
        for i:=9;i<len(first);i++ {first[i]=byte(i)}
        original:=bytes.Clone(first)
        for _,offset:=range []int{5,size/2,size-1} {
            b,cut,ok:=EncodeTLSRecordSplit(first,size,offset)
            if !ok || cut!=offset+5 || !PreservesTLSRecords(first,b,cut) {t.Fatal("valid record rejected",size,offset)}
            b[len(b)-1]^=1
            if !bytes.Equal(first,original) {t.Fatal("output aliases input")}
            if PreservesTLSRecords(first,b,cut) {t.Fatal("corrupt trailing data accepted")}
        }
        for _,offset:=range []int{-1,0,4,size,size+1} {
            b,cut,ok:=EncodeTLSRecordSplit(first,size,offset)
            if ok || b!=nil || cut!=0 {t.Fatal("invalid offset accepted",offset)}
        }
        if _,_,ok:=EncodeTLSRecordSplit(first,size-1,5);ok {t.Fatal("incorrect declared length accepted")}
        for _,truncated:=range [][]byte{nil,first[:8],first[:5+size-1]} {
            if _,_,ok:=EncodeTLSRecordSplit(truncated,size,5);ok {t.Fatal("truncated record accepted")}
        }
        bad:=bytes.Clone(first)
        bad[6],bad[7],bad[8]=0,0,0
        if _,_,ok:=EncodeTLSRecordSplit(bad,size,5);ok {t.Fatal("empty handshake accepted")}
    }
}
