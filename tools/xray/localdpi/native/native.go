//go:build linux && cgo && localdpi_native

// Package native is an opt-in bridge to the pinned ByeDPI C source module.
// It is linked only in explicit experimental APKs, not ordinary builds.
package native

/*
#cgo CFLAGS: -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -I${SRCDIR}/../../../localdpi -I${SRCDIR}/../../../localdpi/vendor/byedpi
#include "packet_inspect.h"
*/
import "C"
import (
    "bytes"
    "unsafe"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

const maxRewrite = 65536

// SplitTLSRecord calls the bounded C wrapper on a separate Go-owned output.
// C retains no pointers; both buffers contain bytes only. The call is
// synchronous. No input bytes or host names are logged.
func SplitTLSRecord(first []byte, offset int) ([]byte,bool) {
    if len(first)>maxRewrite {return nil,false}
    recordLen,ok:=localdpi.CompleteTLSClientHelloRecordLen(first)
    if !ok || offset<=4 || offset>=recordLen {return nil,false}
    out:=make([]byte,len(first)+5)
    rc:=C.dp_tls_record_split((*C.uint8_t)(unsafe.Pointer(&first[0])),
        C.size_t(len(first)),C.size_t(offset),
        (*C.uint8_t)(unsafe.Pointer(&out[0])),C.size_t(len(out)))
    if rc!=0 || !localdpi.PreservesTLSRecords(first,out,offset+5) {return nil,false}
    return out,true
}

// Inspect exposes the existing bounded read-only ByeDPI predicates.
// No hostname, borrowed C pointer, socket or application data is retained.
// ok reports ABI success, not whether a protocol was recognized.
func Inspect(first []byte) (Hint,bool) {
    if len(first)>MaxInspect {return Unknown,false}
    var input *C.uint8_t
    if len(first)>0 {input=(*C.uint8_t)(unsafe.Pointer(&first[0]))}
    var result C.struct_dp_packet_inspection
    rc:=C.dp_packet_inspect(input,C.size_t(len(first)),&result)
    if rc!=0 || result.version!=C.DP_PACKET_INSPECT_VERSION ||
        result.reserved0!=0 || result.reserved1!=0 {
        return Unknown,false
    }
    switch result.hint {
    case C.DP_PACKET_UNKNOWN: return Unknown,true
    case C.DP_PACKET_TLS_CANDIDATE: return TLSCandidate,true
    case C.DP_PACKET_HTTP_CANDIDATE: return HTTPCandidate,true
    default: return Unknown,false
    }
}

// TLSNameAgrees checks only agreement with the common Go parser on a
// complete first record. It cannot introduce a name or a new offset.
// No name bytes or native pointer cross the public interface.
func TLSNameAgrees(first []byte) bool {
    if len(first)>maxRewrite {return false}
    record,ok:=localdpi.CompleteTLSClientHelloRecordLen(first)
    if !ok {return false}
    prefix:=first[:5+record]
    start,end,ok:=localdpi.SNIRange(prefix)
    if !ok {return false}
    return C.dp_tls_name_agrees((*C.uint8_t)(unsafe.Pointer(&prefix[0])),
        C.size_t(len(prefix)),C.size_t(start),C.size_t(end))==1
}

// HTTPHostCase applies the pinned operation only to a synthetic request
// built from a strict Go-validated authority. The original request never
// crosses this C ABI. A separate Go reference checks the entire result.
func HTTPHostCase(first []byte) ([]byte,bool) {
    start,end,ok:=localdpi.HTTPHostRange(first)
    if !ok || end-start<2 || end-start>253 {return nil,false}
    // HTTPHostRange has checked the single Host field and its OWS.
    colon:=start-1
    for colon>=0 && (first[colon]==' ' || first[colon]=='\t') {colon--}
    if colon<4 || first[colon]!=':' || !bytes.EqualFold(first[colon-4:colon],[]byte("Host")) {
        return nil,false
    }
    expected,ok:=localdpi.HTTPHostNameCase(first)
    if !ok {return nil,false}
    var field [4]byte
    rc:=C.dp_http_host_case((*C.uint8_t)(unsafe.Pointer(&first[start])),
        C.size_t(end-start),(*C.uint8_t)(unsafe.Pointer(&field[0])),C.size_t(len(field)))
    if rc!=0 {return nil,false}
    out:=bytes.Clone(first)
    copy(out[colon-4:colon],field[:])
    if !bytes.Equal(out,expected) {return nil,false}
    return out,true
}

// ServerHelloPrefix exposes the bounded upstream predicate only.
// The original input is read-only and the result is not TLS success.
func ServerHelloPrefix(first []byte) bool {
    if len(first)!=6 {return false}
    return C.dp_tls_server_hello_prefix((*C.uint8_t)(unsafe.Pointer(&first[0])),
        C.size_t(len(first)))==1
}
