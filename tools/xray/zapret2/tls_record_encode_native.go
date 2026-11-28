//go:build linux && localdpi_native && cgo

package zapret2

import (
    "errors"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/localdpi/native"
)

// Only an explicit experimental build tag enables this implementation.
// Selection stays in the shared Go planner. Oversize/unsupported input
// retains the established portable implementation.
func encodeTLSRecordSplit(first []byte, recordLen, split int, diagnostic bool) ([]byte, int, bool) {
    // Only diagnostic calls request independent name-parser agreement.
    // SNI-less records retain the existing encoder path. A disagreement
    // uses the already validated portable encoder, never new native offsets.
    if diagnostic {
        if _,_,ok:=SNIRange(first);ok && !native.TLSNameAgrees(first) {
            recordNativeTLSPlan(diagnostic,false)
            return encodeTLSRecordSplitGo(first,recordLen,split)
        }
    }
    if b,ok:=native.SplitTLSRecord(first,split);ok {
        recordNativeTLSPlan(diagnostic,true)
        return b,5+split,true
    }
    recordNativeTLSPlan(diagnostic,false)
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

// No reference fallback on the fixed, independently validated loopback path.
func strictNativeLocalTLSPlan(first []byte) (Plan,error) {
    _,split,ok:=tlsRecordSplitPosition(first)
    if !ok || !native.TLSNameAgrees(first) {
        recordNativeTLSPlan(true,false)
        return Plan{},errors.New("native local TLS name agreement failed")
    }
    b,ok:=native.SplitTLSRecord(first,split)
    if !ok {
        recordNativeTLSPlan(true,false)
        return Plan{},errors.New("native local TLS record encoder failed")
    }
    recordNativeTLSPlan(true,true)
    return Plan{Strategy:TagPrefix+"tlsrec-split",Network:"tcp",Applied:true,Cut:5+split,Rewrite:b},nil
}

// Only the explicitly tagged experiment dispatches the existing TLS method
// locally even when an Alpine planner is selected. No other method changes.
func localNativePlan(tag,network string) bool {
    return network=="tcp" && tag==TagPrefix+"tlsrec-split"
}

// Only the exact built-in loopback fixture in a diagnostic invocation
// can select the local HTTP encoder instead of the chosen Alpine planner.
func localNativeHTTPDiagnostic(tag,network string,first []byte,diagnostic bool) bool {
    return diagnostic && network=="tcp" && tag==TagPrefix+"http-hostcase" && IsLocalHTTPFixture(first)
}

func encodeHTTPHostNameCase(first []byte, diagnostic bool) ([]byte,bool) {
    if diagnostic {
        if IsLocalHTTPFixture(first) {
            // A native candidate must not pass its own self-test by falling
            // back to the portable encoder. Plan validation rejects a
            // missing rewrite of an eligible input.
            return native.HTTPHostCase(first)
        }
        if payload,ok:=native.HTTPHostCase(first);ok {return payload,true}
    }
    return localdpi.HTTPHostNameCase(first)
}

func nativeServerHelloPrefix(first []byte) bool {return native.ServerHelloPrefix(first)}
