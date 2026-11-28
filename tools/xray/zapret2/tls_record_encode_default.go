//go:build linux && (!localdpi_native || !cgo)

package zapret2

import (
    "errors"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func strictNativeLocalTLSPlan(_ []byte) (Plan,error) {return Plan{},errors.New("native TLS fixture encoder not compiled")}

func encodeTLSRecordSplit(first []byte, recordLen, split int, _ bool) ([]byte, int, bool) {
    return encodeTLSRecordSplitGo(first,recordLen,split)
}

func localNativePlan(_, _ string) bool { return false }

func encodeHTTPHostNameCase(first []byte, _ bool) ([]byte,bool) {
    return localdpi.HTTPHostNameCase(first)
}

// No native predicate exists in this build; the shared Go check suffices.
func nativeServerHelloPrefix(_ []byte) bool {return true}

func localNativeHTTPDiagnostic(_, _ string, _ []byte, _ bool) bool {return false}

func nativeLocalTLSChainEnabled() bool {return false}
func strictNativeLocalTLSChainPlan(_ []byte) (Plan,error) {return Plan{},errors.New("native TLS chain not compiled")}
