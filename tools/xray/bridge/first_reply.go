//go:build linux

package bridge

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
    done bool
}

func (h *firstReplyHeader) observe(b []byte) firstReplyKind {
    if h.done || len(b)==0 {return replyPending}
    if h.used==0 && b[0]!=21 {
        h.done=true
        return replyOther
    }
    h.used+=copy(h.prefix[h.used:],b)
    if h.used<5 {return replyPending}
    h.done=true
    if isTLSAlertRecordHeader(h.prefix[:]) {return replyAlert}
    return replyOther
}
