//go:build linux

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi"

// A restricted portable analogue of the multisplit family. No raw
// packet emission, sequence overlap, replay, or arbitrary marker grammar.
func multiSplitPositions(first []byte) (int,int,bool) {
    n,ok:=localdpi.CompleteTLSClientHelloRecordLen(first)
    if !ok {return 0,0,false}
    s,e,ok:=SNIRange(first[:5+n])
    if !ok || e-s<2 {return 0,0,false}
    mid:=s+(e-s)/2
    if mid<=1 || mid>=5+n {return 0,0,false}
    return 1,mid,true
}
