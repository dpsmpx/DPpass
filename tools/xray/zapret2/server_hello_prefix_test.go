//go:build linux

package zapret2

import "testing"

func TestLocalServerHelloPrefix(t *testing.T) {
    if !VerifyLocalServerHelloPrefix([]byte{22,3,3,0,40,2}) {t.Fatal("valid prefix rejected")}
    for _,b:=range [][]byte{nil,{22,3,3,0,40},{22,3,3,0,40,1},
        {21,3,3,0,40,2},{22,2,3,0,40,2},{22,3,5,0,40,2},
        {22,3,3,0,3,2},{22,3,3,64,1,2},{22,3,3,0,40,2,0}} {
        if VerifyLocalServerHelloPrefix(b) {t.Fatal("invalid prefix accepted",b)}
    }
}
