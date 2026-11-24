package localdpi

// Read-only protocol recognition shared by the local planner and future
// executors. This package has no socket or privilege dependencies. A
// recognition hint is not a verified handshake or application response.
import (
    "bytes"
    "encoding/binary"
)

// Minimal QUIC v1/v2 long-header Initial recognizer. Packet length >= 1200
// (RFC 9000) guards against DNS or other random UDP, and the version/type
// check avoids injecting the dummy on unsupported long-header variants.
func IsQUICInitial(b []byte) bool {
	if len(b) < 1200 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	kind := (b[0] >> 4) & 3
	return (version == 0x00000001 && kind == 0) ||
		(version == 0x6b3343cf && kind == 1)
}

// IsTLSClientHelloPrefix checks the TLS record and handshake headers without
// requiring a readable SNI. It is intentionally narrow; random HTTP/2 and
// arbitrary TCP payloads must pass unmodified.
func IsTLSClientHelloPrefix(b []byte) bool {
	return len(b) >= 9 && b[0] == 22 && b[1] == 3 && b[2] <= 4 &&
		b[5] == 1 && binary.BigEndian.Uint16(b[3:5]) >= 4
}

// FirstHostRange accepts TLS SNI or an HTTP/1.x Host header.
func FirstHostRange(b []byte) (start, end int, ok bool) {
	if s, e, yes := SNIRange(b); yes {
		return s, e, true
	}
	return HTTPHostRange(b)
}

// HTTPHostRange recognizes a single Host field in a complete HTTP/1.0
// or HTTP/1.1 header block. Ambiguous or malformed framing is rejected.
// It does not interpret request bodies or validate authority resolution.
func HTTPHostRange(b []byte) (start,end int,ok bool) {
    if len(b)<22 || len(b)>16*1024 {return 0,0,false}
    firstLine:=bytes.Index(b,[]byte("\r\n"))
    headersEnd:=bytes.Index(b,[]byte("\r\n\r\n"))
    if firstLine<=0 || headersEnd<=firstLine {return 0,0,false}
    fields:=bytes.Split(b[:firstLine],[]byte(" "))
    if len(fields)!=3 || len(fields[1])==0 ||
        !(bytes.Equal(fields[2],[]byte("HTTP/1.0")) || bytes.Equal(fields[2],[]byte("HTTP/1.1"))) {
        return 0,0,false
    }
    switch string(fields[0]) {
    case "GET","POST","HEAD","PUT","PATCH","DELETE","OPTIONS":
    default: return 0,0,false
    }
    for _,v:=range fields[1] {
        if v<=32 || v==127 {return 0,0,false}
    }
    found:=false
    for p:=firstLine+2;p<headersEnd; {
        rel:=bytes.Index(b[p:headersEnd+2],[]byte("\r\n"))
        if rel<0 {return 0,0,false}
        lineEnd:=p+rel
        colon:=bytes.IndexByte(b[p:lineEnd],':')
        if colon<=0 {return 0,0,false}
        for _,v:=range b[p:p+colon] {
            if !httpFieldToken(v) {return 0,0,false}
        }
        value:=b[p+colon+1:lineEnd]
        for _,v:=range value {
            if (v<32 && v!='\t') || v==127 {return 0,0,false}
        }
        if bytes.EqualFold(b[p:p+colon],[]byte("Host")) {
            if found {return 0,0,false}
            a,e:=p+colon+1,lineEnd
            for a<e && (b[a]==' ' || b[a]=='\t') {a++}
            for e>a && (b[e-1]==' ' || b[e-1]=='\t') {e--}
            if e-a==0 || e-a>255 {return 0,0,false}
            for _,v:=range b[a:e] {
                if v<=32 || v>=127 || v==',' {return 0,0,false}
            }
            start,end,found=a,e,true
        }
        p=lineEnd+2
    }
    if !found {return 0,0,false}
    return start,end,true
}

func httpFieldToken(v byte) bool {
    return v>='a' && v<='z' || v>='A' && v<='Z' || v>='0' && v<='9' ||
        bytes.IndexByte([]byte("!#$%&'*+-.^_`|~"),v)>=0
}

// SNIRange returns the first server_name host within the available bytes of
// the first ClientHello record. Never consume a later TLS record or a byte
// outside the declared handshake/extension/list. A partial first read can
// still reveal SNI when its complete extension is already present.
func SNIRange(b []byte) (start, end int, ok bool) {
    if !IsTLSClientHelloPrefix(b) { return 0,0,false }
    recordLen:=int(binary.BigEndian.Uint16(b[3:5]))
    if recordLen>16384 {return 0,0,false}
    helloLen:=int(b[6])<<16|int(b[7])<<8|int(b[8])
    if helloLen==0 {return 0,0,false}
    helloEnd:=9+helloLen
    limit:=min(len(b),5+recordLen,helloEnd)
    b=b[:limit]
    p:=9+2+32
    if p+1>len(b) {return 0,0,false}
    sid:=int(b[p])
    if sid>32 {return 0,0,false}
    p+=1+sid
    if p+2>len(b) {return 0,0,false}
    cipherLen:=int(binary.BigEndian.Uint16(b[p:]))
    if cipherLen<2 || cipherLen%2!=0 {return 0,0,false}
    p+=2+cipherLen
    if p+1>len(b) {return 0,0,false}
    compressionLen:=int(b[p])
    if compressionLen==0 {return 0,0,false}
    p+=1+compressionLen
    if p+2>len(b) {return 0,0,false}
    extEnd:=p+2+int(binary.BigEndian.Uint16(b[p:]))
    p+=2
    if extEnd>helloEnd {return 0,0,false}
    available:=min(extEnd,len(b))
    for p+4<=available {
        typ:=binary.BigEndian.Uint16(b[p:])
        size:=int(binary.BigEndian.Uint16(b[p+2:]))
        body:=p+4
        if body+size>available {return 0,0,false}
        if typ==0 {
            if size<5 || b[body+2]!=0 {return 0,0,false}
            listLen:=int(binary.BigEndian.Uint16(b[body:]))
            if listLen!=size-2 {return 0,0,false}
            n:=int(binary.BigEndian.Uint16(b[body+3:]))
            s:=body+5
            if n==0 || s+n>body+size {return 0,0,false}
            return s,s+n,true
        }
        p=body+size
    }
    return 0,0,false
}
