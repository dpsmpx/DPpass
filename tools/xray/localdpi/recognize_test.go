package localdpi

import (
    "bytes"
    "encoding/binary"
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

func boundedHelloFixture() (hello []byte, extLen, sni, listLen int) {
    name:=[]byte("example.test")
    hello=make([]byte,9)
    hello[0],hello[1],hello[2],hello[5]=22,3,3,1
    hello=append(hello,3,3)
    hello=append(hello,make([]byte,32)...)
    hello=append(hello,0,0,2,0x13,0x01,1,0)
    extLen=len(hello)
    hello=append(hello,0,0)
    hello=append(hello,0,0,0,byte(len(name)+5))
    listLen=len(hello)
    hello=append(hello,0,byte(len(name)+3),0,0,byte(len(name)))
    sni=len(hello)
    hello=append(hello,name...)
    hello=append(hello,0x00,0x15,0,2,0,0)
    binary.BigEndian.PutUint16(hello[extLen:],uint16(len(hello)-extLen-2))
    binary.BigEndian.PutUint16(hello[3:],uint16(len(hello)-5))
    length:=len(hello)-9
    hello[6],hello[7],hello[8]=byte(length>>16),byte(length>>8),byte(length)
    return
}

func TestSNIRespectsRecordHandshakeExtensionAndListBounds(t *testing.T) {
    hello,extLen,sni,listLen:=boundedHelloFixture()
    end:=sni+len("example.test")
    for _,b:=range [][]byte{hello,hello[:end],append(bytes.Clone(hello),23,3,3,0,1,0)} {
        s,e,ok:=SNIRange(b)
        if !ok || s!=sni || e!=end {t.Fatal("valid SNI not found",s,e,ok)}
    }
    for cut:=0;cut<end;cut++ {
        if _,_,ok:=SNIRange(hello[:cut]);ok {t.Fatal("truncated SNI accepted",cut)}
    }
    for _,tc:=range []struct{name string; change func([]byte)}{
        {"record ends before name",func(b []byte){binary.BigEndian.PutUint16(b[3:],uint16(sni-5))}},
        {"handshake ends before name",func(b []byte){b[6],b[7],b[8]=0,0,byte(sni-9)}},
        {"extension block ends before name",func(b []byte){binary.BigEndian.PutUint16(b[extLen:],uint16(sni-extLen-2))}},
        {"SNI extension too short",func(b []byte){binary.BigEndian.PutUint16(b[listLen-2:],5)}},
        {"SNI list too short",func(b []byte){binary.BigEndian.PutUint16(b[listLen:],3)}},
        {"invalid TLS version",func(b []byte){b[1]=2}},
        {"oversized record",func(b []byte){binary.BigEndian.PutUint16(b[3:],16385)}},
    } {
        b:=bytes.Clone(hello)
        tc.change(b)
        if _,_,ok:=SNIRange(b);ok {t.Fatal(tc.name)}
    }
    // Fragmented handshake: only a complete extension in the first record
    // is eligible; the next record's header is never treated as host bytes.
    fragment:=bytes.Clone(hello)
    binary.BigEndian.PutUint16(fragment[3:],uint16(end-5))
    if s,e,ok:=SNIRange(fragment);!ok || s!=sni || e!=end {t.Fatal("complete first-record SNI lost")}
}

func FuzzCommonHostRanges(f *testing.F) {
    hello,_,_,_:=boundedHelloFixture()
    f.Add(hello)
    f.Add([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"))
    f.Add([]byte{})
    f.Fuzz(func(t *testing.T,b []byte){
        before:=bytes.Clone(b)
        for _,parse:=range []func([]byte)(int,int,bool){SNIRange,HTTPHostRange,FirstHostRange} {
            s,e,ok:=parse(b)
            if ok && (s<0 || e<=s || e>len(b)) {t.Fatalf("invalid range %d:%d for %d",s,e,len(b))}
        }
        if !bytes.Equal(b,before) {t.Fatal("read-only parser mutated input")}
    })
}
