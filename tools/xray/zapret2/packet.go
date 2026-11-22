//go:build linux

// Package zapret2 owns the single source of truth for packet recognition
// and decoy construction used by the Android Xray adapter and the in-Alpine
// diagnostic executable. It does not acquire Android root privileges.
package zapret2

import (
    "bytes"
    "crypto/rand"
    "encoding/binary"
)

// FakeQUICInitial copies a bounded first Initial datagram, keeping the QUIC
// long header (including DCID/SCID) and replacing only ciphertext bytes.
// This is a best-effort DPI decoy, not a valid QUIC handshake. The packet
// should expire before the destination because of the temporary low TTL.
func FakeQUICInitial(initial []byte) []byte {
	fake := append([]byte(nil), initial...)
	// Header protection and packet-number lengths vary. Keep the first 64
	// bytes, which covers normal QUIC long headers; randomize the rest.
	if len(fake) > 64 {
		if _, err := rand.Read(fake[64:]); err != nil {
			copy(fake[64:], initial[64:])
			fake[len(fake)-1] ^= 0xff
		}
	}
	return fake
}

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

// FakeChunk — подложная часть: те же байты, имя в [start, end) заменено
// случайными строчными буквами той же длины. Имя — не чужой домен:
// сочетание букв без смысла (FAKE_PACKETS.md, §5, «Подложное имя»).
func FakeChunk(part []byte, start, end int) []byte {
	fake := append([]byte(nil), part...)
	if end > len(fake) {
		end = len(fake)
	}
	if start >= end {
		return fake
	}
	letters := make([]byte, end-start)
	if _, err := rand.Read(letters); err != nil {
		for i := range letters {
			letters[i] = 'x'
		}
	}
	for i, r := range letters {
		fake[start+i] = 'a' + r%26
	}
	return fake
}

// SNIRange — где в записи TLS лежит имя сервера (server_name): [start, end)
// байтов имени. ok — это начало ClientHello, и имя целиком в [b].
func SNIRange(b []byte) (start, end int, ok bool) {
	// Запись TLS: тип 22 (handshake), версия, длина; затем сообщение 1 (ClientHello).
	if len(b) < 5+4 || b[0] != 22 || b[5] != 1 {
		return 0, 0, false
	}
	p := 5 + 4 // заголовок записи и сообщения
	p += 2 + 32 // версия и случайное
	if p+1 > len(b) {
		return 0, 0, false
	}
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return 0, 0, false
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // наборы шифров
	if p+1 > len(b) {
		return 0, 0, false
	}
	p += 1 + int(b[p]) // методы сжатия
	if p+2 > len(b) {
		return 0, 0, false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[p:])
		size := int(binary.BigEndian.Uint16(b[p+2:]))
		body := p + 4
		if body+size > len(b) {
			return 0, 0, false
		}
		if typ == 0 { // server_name: список, первый — host_name
			if size < 5 || b[body+2] != 0 {
				return 0, 0, false
			}
			n := int(binary.BigEndian.Uint16(b[body+3:]))
			s := body + 5
			if n == 0 || s+n > body+size {
				return 0, 0, false
			}
			return s, s + n, true
		}
		p = body + size
	}
	return 0, 0, false
}


// SplitTLSRecordClientHello rewrites a complete, single-record ClientHello
// into two valid TLS handshake records. It preserves every handshake byte and
// all trailing TLS records; only one additional five-byte record header is
// introduced. The returned cut is the boundary between the two records.
// Incomplete or already fragmented handshakes are deliberately left intact.
func SplitTLSRecordClientHello(first []byte) ([]byte, int, bool) {
    if !IsTLSClientHelloPrefix(first) {
        return nil, 0, false
    }
    recordLen := int(binary.BigEndian.Uint16(first[3:5]))
    if recordLen < 8 || recordLen > 16384 || len(first) < 5+recordLen {
        return nil, 0, false
    }
    body := first[5 : 5+recordLen]
    // The TLS handshake header is type(1) + length(3). Require exactly
    // one complete ClientHello before rewriting its record framing.
    handshakeLen := int(body[1])<<16 | int(body[2])<<8 | int(body[3])
    if handshakeLen < 4 || handshakeLen+4 != recordLen {
        return nil, 0, false
    }
    // Split the handshake after its four-byte header. Keep both TLS
    // record fragments nonempty and within the TLS 16 KiB record limit.
    leftLen := recordLen / 2
    if leftLen < 4 || leftLen >= recordLen {
        return nil, 0, false
    }
    rightLen := recordLen - leftLen
    out := make([]byte, 0, len(first)+5)
    out = append(out, first[:5]...)
    binary.BigEndian.PutUint16(out[3:5], uint16(leftLen))
    out = append(out, body[:leftLen]...)
    cut := len(out)
    out = append(out, first[:3]...)
    out = append(out, byte(rightLen>>8), byte(rightLen))
    out = append(out, body[leftLen:]...)
    out = append(out, first[5+recordLen:]...)
    return out, cut, true
}
