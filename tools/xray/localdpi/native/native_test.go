//go:build linux && localdpi_native && cgo

package native

import (
    "bytes"
    "encoding/binary"
    "testing"
)

func TestBoundedNativeSplit(t *testing.T) {
    first:=make([]byte,5+64+5)
    copy(first,[]byte{22,3,3,0,64,1,0,0,60})
    for i:=9;i<len(first);i++ {first[i]=byte(i)}
    original:=append([]byte(nil),first...)
    for offset:=5;offset<64;offset++ {
        got,ok:=SplitTLSRecord(first,offset)
        if !ok || len(got)!=len(first)+5 {t.Fatalf("offset %d rejected",offset)}
        if binary.BigEndian.Uint16(got[3:5])!=uint16(offset) ||
            binary.BigEndian.Uint16(got[8+offset:10+offset])!=uint16(64-offset) ||
            !bytes.Equal(got[5:5+offset],first[5:5+offset]) ||
            !bytes.Equal(got[10+offset:],first[5+offset:]) ||
            !bytes.Equal(first,original) {t.Fatalf("offset %d changed bytes",offset)}
    }
    for _,offset:=range []int{-1,0,4,64,65536} {
        if b,ok:=SplitTLSRecord(first,offset);ok || b!=nil {t.Fatal("invalid offset accepted",offset)}
    }
    if _,ok:=SplitTLSRecord(first[:8],5);ok {t.Fatal("truncated input accepted")}
}
