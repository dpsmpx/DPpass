//go:build linux && localdpi_native && cgo

package native

import (
    "bytes"
    "encoding/binary"
    "testing"

    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func recordFixture(size int) []byte {
    first:=make([]byte,5+size+6)
    copy(first,[]byte{22,3,3,0,0,1,0,0,0})
    binary.BigEndian.PutUint16(first[3:5],uint16(size))
    hello:=size-4
    first[6],first[7],first[8]=byte(hello>>16),byte(hello>>8),byte(hello)
    for i:=9;i<len(first);i++ {first[i]=byte(i*31)}
    return first
}

// Exercise both accepted and rejected inputs. Compare the existing
// portable reference against the opt-in native wrapper, not network behavior.
func FuzzNativeRecordParity(f *testing.F) {
    for _,size:=range []int{12,64,512,16384} {
        b:=recordFixture(size)
        f.Add(b,5)
        f.Add(b,size-1)
        f.Add(b,size)
        f.Add(b[:8],5)
    }
    f.Add([]byte{},0)
    f.Fuzz(func(t *testing.T,b []byte,offset int){
        if len(b)>maxRewrite {return}
        before:=bytes.Clone(b)
        recordLen,_:=localdpi.CompleteTLSClientHelloRecordLen(b)
        want,cut,portableOK:=localdpi.EncodeTLSRecordSplit(b,recordLen,offset)
        got,nativeOK:=SplitTLSRecord(b,offset)
        if portableOK!=nativeOK || !bytes.Equal(got,want) {
            t.Fatal("native/reference result mismatch")
        }
        if nativeOK && !localdpi.PreservesTLSRecords(b,got,cut) {
            t.Fatal("output integrity mismatch")
        }
        if !bytes.Equal(b,before) {t.Fatal("input modified")}
        if len(b)<=MaxInspect {
            h,ok:=Inspect(b)
            h2,ok2:=Inspect(b)
            if !ok || !ok2 || h>HTTPCandidate || h!=h2 {
                t.Fatal("invalid or non-deterministic hint")
            }
        }
        if !bytes.Equal(b,before) {t.Fatal("inspection modified input")}
    })
}

// All workers read a shared immutable fixture. Their outputs must be
// independently owned. This tests the actual cgo call on synthetic data.
func TestConcurrentNativeCalls(t *testing.T) {
    first:=recordFixture(512)
    original:=bytes.Clone(first)
    for worker:=0;worker<8;worker++ {
        t.Run("worker-"+string(rune('0'+worker)),func(t *testing.T){
            t.Parallel()
            for i:=0;i<128;i++ {
                offset:=5+(worker*128+i)%507
                want,cut,ok:=localdpi.EncodeTLSRecordSplit(first,512,offset)
                got,nativeOK:=SplitTLSRecord(first,offset)
                if !ok || !nativeOK || !bytes.Equal(want,got) ||
                    !localdpi.PreservesTLSRecords(first,got,cut) {
                    t.Fatal("concurrent encoder disagreement")
                }
                got[len(got)-1]^=1
                if !bytes.Equal(first,original) {t.Fatal("input aliased or mutated")}
                hint,ok:=Inspect(first)
                if !ok || hint!=TLSCandidate {t.Fatal("concurrent inspection mismatch")}
            }
        })
    }
}
