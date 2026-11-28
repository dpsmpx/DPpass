//go:build linux && localdpi_native && cgo

package zapret2

import (
    "bytes"
    "path/filepath"
    "testing"
    "github.com/dpsmpx/dppass/tools/xray/localdpi/native"
)

func TestNativeTLSRecordEncoderMatchesPortable(t *testing.T) {
    for _,recordLen:=range []int{12,32,64,512,16384} {
        first:=make([]byte,5+recordLen+5)
        first[0],first[1],first[2]=22,3,3
        first[3],first[4]=byte(recordLen>>8),byte(recordLen)
        first[5]=1
        hello:=recordLen-4
        first[6],first[7],first[8]=byte(hello>>16),byte(hello>>8),byte(hello)
        for i:=9;i<len(first);i++ {first[i]=byte(i*37)}
        for _,offset:=range []int{5,recordLen/2,recordLen-1} {
            want,cut,_:=encodeTLSRecordSplitGo(first,recordLen,offset)
            got,ok:=native.SplitTLSRecord(first,offset)
            if !ok || !bytes.Equal(want,got) {t.Fatalf("native parity length=%d offset=%d",recordLen,offset)}
            actual,actualCut,ok:=encodeTLSRecordSplit(first,recordLen,offset,false)
            if !ok || actualCut!=cut || !bytes.Equal(actual,want) {t.Fatal("planner parity")}
        }
    }
}

func TestTaggedTLSPlanUsesNativeWithoutPlannerIPC(t *testing.T) {
    previous:=PlannerSocket()
    t.Cleanup(func(){_ = SetPlannerSocket(previous)})
    if err:=SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    first:=tlsClientHelloFixture(t,"example.test")
    before,fallbackBefore:=NativeTLSRecordStats()
    p,err:=PlanFor(TagPrefix+"tlsrec-split","tcp",first)
    if err!=nil || !p.Applied || len(p.Rewrite)!=len(first)+5 {t.Fatalf("native plan: %+v %v",p,err)}
    after,fallbackAfter:=NativeTLSRecordStats()
    if after!=before+1 || fallbackAfter!=fallbackBefore {t.Fatalf("native encoder not used: %d/%d -> %d/%d",before,fallbackBefore,after,fallbackAfter)}
    if _,err:=PlanFor(TagPrefix+"split-1","tcp",first);err==nil {t.Fatal("other method silently replaced failed Alpine planner")}
    if _,err:=PlanFor(TagPrefix+"tlsrec-split","udp",first);err==nil {t.Fatal("wrong transport selected local encoder")}
    if _,err:=PlanFor(TagPrefix+"tlsrec-split","tcp",make([]byte,MaxFirst+1));err==nil {t.Fatal("oversize bypassed guard")}
}

func TestDiagnosticNativeTLSPlanDoesNotChangeLiveCounters(t *testing.T) {
    first:=tlsClientHelloFixture(t,"example.test")
    live,liveFallback:=NativeTLSRecordStats()
    diagnostic,diagnosticFallback:=diagnosticNativeTLSRecordStats()
    p,err:=PlanForDiagnostic(TagPrefix+"tlsrec-split","tcp",first)
    if err!=nil || !p.Applied || len(p.Rewrite)!=len(first)+5 {t.Fatal("diagnostic plan failed",err)}
    n,f:=NativeTLSRecordStats()
    dn,df:=diagnosticNativeTLSRecordStats()
    if n!=live || f!=liveFallback || dn!=diagnostic+1 || df!=diagnosticFallback {
        t.Fatal("diagnostic encoder accounting mixed with live counters")
    }
}

func TestStrictLocalTLSFixtureDoesNotUseReferenceFallback(t *testing.T) {
    previous:=PlannerSocket()
    t.Cleanup(func(){_ = SetPlannerSocket(previous)})
    if err:=SetPlannerSocket(filepath.Join(t.TempDir(),"missing.sock"));err!=nil {t.Fatal(err)}
    first:=tlsClientHelloFixture(t,"example.com")
    before,fb:=diagnosticNativeTLSRecordStats()
    live,liveFB:=NativeTLSRecordStats()
    p,err:=PlanForLocalTLSFixture(first)
    if err!=nil || !p.Applied || len(p.Rewrite)!=len(first)+5 {t.Fatal("strict native fixture",err)}
    after,afterFB:=diagnosticNativeTLSRecordStats()
    if after!=before+1 || afterFB!=fb {t.Fatal("strict fixture used reference")}
    for _,bad:=range [][]byte{nil,first[:len(first)-1],append(append([]byte(nil),first...),0),tlsClientHelloFixture(t,"example.test")} {
        if _,err:=PlanForLocalTLSFixture(bad);err==nil {t.Fatal("invalid fixture accepted")}
    }
    final,finalFB:=diagnosticNativeTLSRecordStats()
    l,lf:=NativeTLSRecordStats()
    if final!=after || finalFB!=afterFB || l!=live || lf!=liveFB {t.Fatal("invalid fixture or local diagnostics affected accounting")}
}
