//go:build linux

package zapret2

import "encoding/binary"

// SplitTLSRecordClientHello re-encodes a *complete* first TLS ClientHello
// record into two valid handshake records. It preserves the handshake bytes,
// follows RFC 8446 record framing, and leaves any following records intact.
// The caller sends the two records in separate TCP writes. This combines
// TLS-record and TCP segmentation, without fake packets, root or TLS keys.
//
// It deliberately declines incomplete/oversized/non-TLS records instead of
// modifying arbitrary application data. No plaintext is retained or logged.
func SplitTLSRecordClientHello(first []byte) (rewritten []byte, firstRecordEnd int, ok bool) {
    if !IsTLSClientHelloPrefix(first) || len(first) < 9 { return nil, 0, false }
    recordLen := int(binary.BigEndian.Uint16(first[3:5]))
    if recordLen < 12 || recordLen > 16*1024 || len(first) < 5+recordLen {
        return nil, 0, false
    }
    // The first handshake message must fit wholly inside this record.
    helloLen := int(first[6])<<16 | int(first[7])<<8 | int(first[8])
    if helloLen == 0 || helloLen+4 > recordLen { return nil, 0, false }

    // Break inside the SNI when available, otherwise in the handshake body.
    // Keep the complete 4-byte handshake header inside the first record.
    split := recordLen / 2
    if s, e, found := SNIRange(first[:5+recordLen]); found {
        split = s - 5 + (e-s)/2
    }
    if split <= 4 || split >= recordLen { return nil, 0, false }

    return encodeTLSRecordSplit(first, recordLen, split)
}
