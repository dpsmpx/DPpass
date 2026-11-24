package localdpi

import (
    "bytes"
    "testing"
)

func TestCommonRecognitionDoesNotMutateInput(t *testing.T) {
    http:=[]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
    before:=bytes.Clone(http)
    start,end,ok:=FirstHostRange(http)
    if !ok || string(http[start:end])!="example.test" {t.Fatal("HTTP host not recognized")}
    if IsTLSClientHelloPrefix(http) || IsQUICInitial(http) || !bytes.Equal(before,http) {t.Fatal("wrong recognition or mutated input")}
    hello:=[]byte{22,3,3,0,4,1,0,0,0}
    if !IsTLSClientHelloPrefix(hello) {t.Fatal("legacy prefix not recognized")}
    if _,_,ok:=FirstHostRange(hello);ok {t.Fatal("invented hostname")}
    for _,version:=range [][]byte{{0xc0,0,0,0,1},{0xd0,0x6b,0x33,0x43,0xcf}} {
        initial:=make([]byte,1200)
        copy(initial,version)
        if !IsQUICInitial(initial) || IsQUICInitial(initial[:1199]) {t.Fatal("QUIC recognition changed")}
    }
}
