//go:build linux && localdpi_native && cgo

package zapret2

import (
    "bytes"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi/native"
)

func TestNativeTLSRecordEncoderMatchesPortable(t *testing.T) {
    for _,recordLen:=range []int{12,32,64,512,16384} {
        first:=make([]byte,5+recordLen+5)
        first[0],first[1],first[2]=22,3,3
        first[3],first[4]=byte(recordLen>>8),byte(recordLen)
        first[5]=1
        hello:=recordLen-4
        first[6],first[7],first[8]=byte(hello>>16),byte(hello>>8),byte(hello)
        for i:=9;i<len(first);i++ {first[i]=byte(i*37)}
        for _,offset:=range []int{5,recordLen/2,recordLen-1} {
            want,cut,_:=encodeTLSRecordSplitGo(first,recordLen,offset)
            got,ok:=native.SplitTLSRecord(first,offset)
            if !ok || !bytes.Equal(want,got) {t.Fatalf("native parity length=%d offset=%d",recordLen,offset)}
            actual,actualCut,ok:=encodeTLSRecordSplit(first,recordLen,offset)
            if !ok || actualCut!=cut || !bytes.Equal(actual,want) {t.Fatal("planner parity")}
        }
    }
}
