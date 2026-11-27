//go:build linux

package bridge

import "sync/atomic"

type firstReplyKind uint8
const (
    replyPending firstReplyKind = iota
    replyAlert
    replyOther
)

// This classifier reports exactly one outcome. Only an alert-looking
// first byte requires waiting for more data; never buffer arbitrary data.
type firstReplyHeader struct {
    prefix [5]byte
    used int
    // Read owns prefix/used; Close may inspect the terminal result concurrently.
    result atomic.Uint32
}

func (h *firstReplyHeader) observe(b []byte) firstReplyKind {
    if h.classification()!=replyPending || len(b)==0 {return replyPending}
    if h.used==0 && b[0]!=21 {
        h.result.Store(uint32(replyOther))
        return replyOther
    }
    h.used+=copy(h.prefix[h.used:],b)
    if h.used<5 {return replyPending}
    result:=replyOther
    if isTLSAlertRecordHeader(h.prefix[:]) {result=replyAlert}
    h.result.Store(uint32(result))
    return result
}

// Only a classified non-alert reply can contribute downstream evidence.
// A partial alert-like header is ambiguous, even if the socket closes.
func (h *firstReplyHeader) classification() firstReplyKind {
    return firstReplyKind(h.result.Load())
}

func (h *firstReplyHeader) admitsDownstream() bool {
    return h.classification()==replyOther
}
