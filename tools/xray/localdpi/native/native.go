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

const httpCaseFixture = "POST /self-check HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\n\r\nbody"

// HTTPHostCaseFixture invokes upstream MH_HMIX only on the fixed local
// request. The strict Go reference independently verifies every byte.
func HTTPHostCaseFixture(first []byte) ([]byte,bool) {
    if !bytes.Equal(first,[]byte(httpCaseFixture)) {return nil,false}
    expected,ok:=localdpi.HTTPHostNameCase(first)
    if !ok {return nil,false}
    out:=make([]byte,len(first))
    rc:=C.dp_http_host_case_fixture((*C.uint8_t)(unsafe.Pointer(&first[0])),
        C.size_t(len(first)),(*C.uint8_t)(unsafe.Pointer(&out[0])),C.size_t(len(out)))
    if rc!=0 || !bytes.Equal(out,expected) {return nil,false}
    return out,true
}
