package localdpi

import (
    "bytes"
    "encoding/binary"
)

// PreservesTLSRecords checks that a proposed two-record representation
// differs only in the record headers. It is a read-only integrity check,
// not a TLS handshake validator. No sockets or payload retention.
func PreservesTLSRecords(original, rewritten []byte, cut int) bool {
    if !IsTLSClientHelloPrefix(original) || len(rewritten)!=len(original)+5 {return false}
    recordLen:=int(binary.BigEndian.Uint16(original[3:5]))
    if recordLen<12 || recordLen>16384 || recordLen>len(original)-5 {return false}
    helloLen:=int(original[6])<<16|int(original[7])<<8|int(original[8])
    if helloLen==0 || helloLen>recordLen-4 {return false}
    if cut<=9 || cut>=5+recordLen {return false}
    firstLen:=cut-5
    secondLen:=recordLen-firstLen
    return bytes.Equal(rewritten[:3],original[:3]) &&
        int(binary.BigEndian.Uint16(rewritten[3:5]))==firstLen &&
        bytes.Equal(rewritten[cut:cut+3],original[:3]) &&
        int(binary.BigEndian.Uint16(rewritten[cut+3:cut+5]))==secondLen &&
        bytes.Equal(rewritten[5:cut],original[5:cut]) &&
        bytes.Equal(rewritten[cut+5:],original[cut:])
}
