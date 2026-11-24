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

// Host header is only recognized in a complete HTTP/1.x request, avoiding
// accidental manipulation of arbitrary TCP streams or partial headers.
func HTTPHostRange(b []byte) (start, end int, ok bool) {
	if len(b) < 22 || len(b) > 16*1024 {
		return 0, 0, false
	}
	firstLine := bytes.Index(b, []byte("\r\n"))
	headersEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if firstLine <= 0 || headersEnd <= firstLine || !bytes.Contains(b[:firstLine], []byte(" HTTP/1.")) {
		return 0, 0, false
	}
	method := b[:firstLine]
	valid := false
	for _, m := range [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("PATCH "), []byte("DELETE "), []byte("OPTIONS ")} {
		if bytes.HasPrefix(method, m) {
			valid = true
			break
		}
	}
	if !valid {
		return 0, 0, false
	}
	for p := firstLine + 2; p < headersEnd; {
		rel := bytes.Index(b[p:headersEnd+2], []byte("\r\n"))
		if rel < 0 { return 0, 0, false }
		lineEnd := p + rel
		colon := bytes.IndexByte(b[p:lineEnd], ':')
		if colon > 0 && bytes.EqualFold(b[p:p+colon], []byte("Host")) {
			a := p + colon + 1
			for a < lineEnd && (b[a] == ' ' || b[a] == '\t') { a++ }
			e := lineEnd
			for e > a && (b[e-1] == ' ' || b[e-1] == '\t') { e-- }
			if e-a == 0 || e-a > 255 || bytes.IndexAny(b[a:e], " \t\r\n") >= 0 {
				return 0, 0, false
			}
			return a, e, true
		}
		p = lineEnd + 2
	}
	return 0, 0, false
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
