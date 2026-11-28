//go:build linux

package zapret2

import "github.com/dpsmpx/dppass/tools/xray/localdpi"

// Only the synthetic fixture's complete single record is eligible.
func localTLSRecordChainPositions(first []byte) (int,int,bool) {
    n,ok:=localdpi.CompleteTLSClientHelloRecordLen(first)
    if !ok || len(first)!=5+n {return 0,0,false}
    s,e,ok:=SNIRange(first)
    if !ok || string(first[s:e])!="example.com" {return 0,0,false}
    a,b:=n/3,2*n/3
    if a<=4 || b<=a || b>=n {return 0,0,false}
    return a,b,true
}
