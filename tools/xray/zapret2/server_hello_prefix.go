//go:build linux

package zapret2

import "encoding/binary"

// VerifyLocalServerHelloPrefix checks a fixed six-byte record prefix and
// optionally the pinned native predicate. Only local diagnostics call it.
// It is not a certificate, complete handshake or content verifier.
func VerifyLocalServerHelloPrefix(first []byte) bool {
    if len(first)!=6 || first[0]!=22 || first[1]!=3 || first[2]>4 || first[5]!=2 {
        return false
    }
    size:=binary.BigEndian.Uint16(first[3:5])
    return size>=4 && size<=16384 && nativeServerHelloPrefix(first)
}
