//go:build linux && localdpi_native && cgo

package native

import (
    "bytes"
    "encoding/binary"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
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

func TestNativeAndPortableShareRecordContract(t *testing.T) {
    first:=make([]byte,5+64+6)
    copy(first,[]byte{22,3,3,0,64,1,0,0,60})
    for i:=9;i<len(first);i++ {first[i]=byte(i*17)}
    original:=bytes.Clone(first)
    for offset:=0;offset<=65;offset++ {
        want,cut,portableOK:=localdpi.EncodeTLSRecordSplit(first,64,offset)
        got,nativeOK:=SplitTLSRecord(first,offset)
        if portableOK!=nativeOK || !bytes.Equal(got,want) {
            t.Fatal("encoder disagreement",offset)
        }
        if nativeOK && !localdpi.PreservesTLSRecords(first,got,cut) {
            t.Fatal("native output failed common contract")
        }
        if !bytes.Equal(first,original) {t.Fatal("input changed")}
    }
    for _,change:=range []func([]byte){
        func(b []byte){b[0]=23},
        func(b []byte){b[2]=5},
        func(b []byte){b[5]=2},
        func(b []byte){b[6],b[7],b[8]=0,0,0},
        func(b []byte){b[8]=65},
        func(b []byte){b[3],b[4]=0,100},
    } {
        b:=bytes.Clone(first)
        change(b)
        if _,ok:=SplitTLSRecord(b,5);ok {t.Fatal("invalid native input accepted")}
        if _,_,ok:=localdpi.EncodeTLSRecordSplit(b,64,5);ok {t.Fatal("invalid portable input accepted")}
    }
    if _,ok:=SplitTLSRecord(make([]byte,maxRewrite+1),5);ok {t.Fatal("native allocation cap bypassed")}
}
