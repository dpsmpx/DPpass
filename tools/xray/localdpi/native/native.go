//go:build linux && cgo && localdpi_native

// Package native is an opt-in bridge to the pinned ByeDPI C source module.
// It is not part of ordinary builds or the shipped APK.
package native

/*
#cgo CFLAGS: -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -I${SRCDIR}/../../../localdpi -I${SRCDIR}/../../../localdpi/vendor/byedpi
#include "packet_inspect.h"
*/
import "C"
import (
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
