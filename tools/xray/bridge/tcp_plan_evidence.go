//go:build linux

package bridge

import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

// A chosen method and an executed method are distinct. The planner's
// one-byte fallback may preserve the connection, but it is not evidence
// that the originally chosen TLS record/fake/disorder method succeeded.
func tcpPlanMatchesSelection(pick *adaptivePick, p zapret2.Plan) bool {
    if !socketPickAdmissible(pick) || pick.flow.Transport==localdpi.QUIC ||
        p.Network!="tcp" || p.Strategy!=zapret2.TagPrefix+pick.flow.MethodID {
        return false
    }
    if pick.flow.MethodID=="pass" {return !p.Applied}
    if !p.Applied {return false}
    if pick.flow.MethodID=="split-1" {return p.Cut==1}
    return p.Cut>1
}
