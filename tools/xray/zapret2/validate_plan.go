//go:build linux

package zapret2

import (
    "errors"
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
)

// validatePlan is the executor-side wire contract. It checks returned
// metadata and actual TLS payload integrity before any socket write.
// It does not select a replacement strategy or retry an application request.
func validatePlan(tag,network string,first []byte,p Plan) error {
    mode,known,err:=ParseTag(tag)
    if err!=nil || !known || mode.Kind==Auto ||
        (network!="tcp" && network!="udp") ||
        p.Strategy!=tag || p.Network!=network || p.TTL!=mode.TTL {
        return errors.New("invalid planner metadata")
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
            len(p.Rewrite)!=0 || p.Repeats<1 || p.Repeats>16 || len(p.Fake)!=len(first) {
            return errors.New("invalid UDP plan")
        }
        return nil
    }
    if p.Repeats!=0 {return errors.New("unexpected TCP repeat count")}
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
    } else if len(p.Fake)!=0 {
        return errors.New("unexpected TCP auxiliary data")
    }
    return nil
}
