//go:build linux

// Package zapret2 owns the single source of truth for packet recognition
// and decoy construction used by the Android Xray adapter and the in-Alpine
// diagnostic executable. It does not acquire Android root privileges.
package zapret2

import (
    "crypto/rand"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
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

// Compatibility delegates: recognition is owned by the common library.
func IsQUICInitial(b []byte) bool { return localdpi.IsQUICInitial(b) }
func IsTLSClientHelloPrefix(b []byte) bool { return localdpi.IsTLSClientHelloPrefix(b) }
func FirstHostRange(b []byte) (int,int,bool) { return localdpi.FirstHostRange(b) }
func HTTPHostRange(b []byte) (int,int,bool) { return localdpi.HTTPHostRange(b) }
func SNIRange(b []byte) (int,int,bool) { return localdpi.SNIRange(b) }

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

