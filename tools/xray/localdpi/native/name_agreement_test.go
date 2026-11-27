//go:build linux && cgo && localdpi_native

package native

import (
    "bytes"
    "encoding/binary"
    "testing"
)

func agreementFixture() []byte {
    name:=[]byte("example.test")
    b:=[]byte{22,3,3,0,0,1,0,0,0,3,3}
    b=append(b,make([]byte,32)...)
    b=append(b,0,0,2,0x13,1,1,0)
    ext:=len(b)
    b=append(b,0,0,0,0,0,byte(len(name)+5),0,byte(len(name)+3),0,0,byte(len(name)))
    b=append(b,name...)
    b=append(b,0,21,0,4,0,0,0,0)
    binary.BigEndian.PutUint16(b[ext:ext+2],uint16(len(b)-ext-2))
    binary.BigEndian.PutUint16(b[3:5],uint16(len(b)-5))
    b[8]=byte(len(b)-9)
    return b
}

func TestNativeTLSNameAgreement(t *testing.T) {
    first:=agreementFixture()
    original:=bytes.Clone(first)
    if !TLSNameAgrees(first) {t.Fatal("valid range disagreement")}
    if !TLSNameAgrees(append(bytes.Clone(first),23,3,3,0,1,0)) {
        t.Fatal("trailing record affected comparison")
    }
    for n:=0;n<len(first);n++ {
        if TLSNameAgrees(first[:n]) {t.Fatal("truncated record accepted",n)}
    }
    for _,change:=range []func([]byte){
        func(b []byte){b[0]=23},
        func(b []byte){b[8]=0},
        func(b []byte){b[3],b[4]=0,12},
        func(b []byte){b[43]=255},
    } {
        b:=bytes.Clone(first)
        change(b)
        if TLSNameAgrees(b) {t.Fatal("invalid fixture accepted")}
    }
    if !bytes.Equal(first,original) {t.Fatal("native parser mutated input")}
    if TLSNameAgrees(make([]byte,maxRewrite+1)) {t.Fatal("oversized input accepted")}
}
