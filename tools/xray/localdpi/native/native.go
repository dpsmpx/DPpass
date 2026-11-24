//go:build linux && cgo && localdpi_native

// Package native is an opt-in bridge to the pinned ByeDPI C source module.
// It is not part of ordinary builds or the shipped APK.
package native

/*
#cgo CFLAGS: -std=c99 -D_DEFAULT_SOURCE -D_GNU_SOURCE -I${SRCDIR}/../../../localdpi -I${SRCDIR}/../../../localdpi/vendor/byedpi
#include "packet_inspect.h"
*/
import "C"
import "unsafe"

const maxRewrite = 65536

// SplitTLSRecord calls the bounded C wrapper on a separate Go-owned output.
// C retains no pointers; both buffers contain bytes only. The call is
// synchronous. No input bytes or host names are logged.
func SplitTLSRecord(first []byte, offset int) ([]byte,bool) {
    if len(first)<9 || len(first)>maxRewrite || offset<0 || offset>16384 {
        return nil,false
    }
    out:=make([]byte,len(first)+5)
    rc:=C.dp_tls_record_split((*C.uint8_t)(unsafe.Pointer(&first[0])),
        C.size_t(len(first)),C.size_t(offset),
        (*C.uint8_t)(unsafe.Pointer(&out[0])),C.size_t(len(out)))
    if rc!=0 {return nil,false}
    return out,true
}
