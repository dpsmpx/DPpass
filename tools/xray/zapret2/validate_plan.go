//go:build linux

package zapret2

import (
    "errors"
    "bytes"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

// validatePlan is the executor-side wire contract. It checks returned
// metadata and actual TLS payload integrity before any socket write.
// It does not select a replacement strategy or retry an application request.
func validatePlan(tag,network string,first []byte,p Plan) error {
    mode,err:=validateRequest(tag,network,first)
    if err!=nil ||
        p.Strategy!=tag || p.Network!=network || p.TTL!=mode.TTL {
        return errors.New("invalid planner metadata")
    }
    expectedCut,expectedApplied:=expectedPlanAction(mode,network,first)
    if p.Applied!=expectedApplied || p.Cut!=expectedCut {
        return errors.New("planner action does not match requested method")
    }
    if !p.Applied {
        if p.Cut!=0 || len(p.Fake)!=0 || len(p.Rewrite)!=0 || p.Repeats!=0 {
            return errors.New("unexpected data in unapplied plan")
        }
        return nil
    }
    if mode.Kind==Pass {return errors.New("baseline cannot return an applied plan")}
    if network=="udp" {
        if mode.Kind!=Fake || !IsQUICInitial(first) || p.Cut!=0 ||
            len(p.Rewrite)!=0 || p.Repeats!=6 || len(p.Fake)!=len(first) ||
            !bytes.Equal(p.Fake[:64],first[:64]) {
            return errors.New("invalid UDP plan")
        }
        return nil
    }
    if p.Repeats!=0 {return errors.New("unexpected TCP repeat count")}
    if mode.Kind==HTTPHostCase {
        // Exact deterministic encoding, not merely any case-folded Host.
        expected,ok:=localdpi.HTTPHostNameCase(first)
        if !ok || len(p.Fake)!=0 || !bytes.Equal(expected,p.Rewrite) {
            return errors.New("invalid HTTP Host name rewrite")
        }
        return nil
    }
    if mode.Kind==TLSRecordSplit {
        if len(p.Fake)!=0 || !localdpi.PreservesTLSRecords(first,p.Rewrite,p.Cut) {
            return errors.New("invalid TLS record rewrite")
        }
        return nil
    }
    if len(p.Rewrite)!=0 || p.Cut<1 || p.Cut>=len(first) {
        return errors.New("invalid TCP plan")
    }
    if mode.Kind==Fake {
        if p.Cut==1 && IsTLSClientHelloPrefix(first) && len(p.Fake)==0 {return nil}
        if len(p.Fake)!=p.Cut {return errors.New("invalid TCP auxiliary data length")}
        start,_,found:=FirstHostRange(first)
        if !found || start<0 || start>p.Cut || !bytes.Equal(p.Fake[:start],first[:start]) {
            return errors.New("invalid TCP auxiliary data prefix")
        }
    } else if len(p.Fake)!=0 {
        return errors.New("unexpected TCP auxiliary data")
    }
    return nil
}


// expectedPlanAction is a pure check of eligibility and position. It never
// generates another plan, modifies input or increments encoder counters.
func expectedPlanAction(mode Mode,network string,first []byte) (int,bool) {
    if mode.Kind==Pass {return 0,false}
    if network=="udp" {return 0,mode.Kind==Fake && IsQUICInitial(first)}
    switch mode.Kind {
    case HTTPHostCase:
        _,_,ok:=localdpi.HTTPHostRange(first)
        return 0,ok
    case TLSRecordSplit:
        _,split,ok:=tlsRecordSplitPosition(first)
        if !ok {return 0,false}
        return 5+split,true
    case SplitFirst:
        if IsTLSClientHelloPrefix(first) {return 1,true}
    case SplitSecond:
        if IsTLSClientHelloPrefix(first) && len(first)>2 {return 2,true}
    case Split,Disorder,Fake:
        if s,e,ok:=FirstHostRange(first);ok {return s+(e-s)/2,true}
        if IsTLSClientHelloPrefix(first) {return 1,true}
    }
    return 0,false
}
