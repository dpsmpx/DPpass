//go:build linux

package bridge

// Privacy-safe process-wide counters at the protected experimental socket.
// They do not establish HTTP/TLS success or identify any destination.
import (
    "context"
    "errors"
    "net"
    "sync/atomic"
    "syscall"
)

var zapret2Stage struct {
    tcpDialOK atomic.Int64
    tcpDialTimeout atomic.Int64
    tcpDialRefused atomic.Int64
    tcpDialUnreachable atomic.Int64
    tcpDialOther atomic.Int64
    tcpHelloSent atomic.Int64
    tcpHelloFailed atomic.Int64
    tcpFirstReply atomic.Int64
    tcpClosedNoReply atomic.Int64
    tcpFirstTLSAlert atomic.Int64
    tcpReadTimeout atomic.Int64
    udpInitialSent atomic.Int64
    udpInitialFailed atomic.Int64
    udpFirstReply atomic.Int64
    udpClosedNoReply atomic.Int64
}

// Zapret2Stages: fifteen monotonically increasing process-wide counters
// in the order documented in engine.Zapret2Stages. DNS, DoH and HTTP
// application outcomes cannot be observed at this socket boundary.
func Zapret2Stages() [15]int64 {
    return [15]int64{
        zapret2Stage.tcpDialOK.Load(),
        zapret2Stage.tcpDialTimeout.Load(),
        zapret2Stage.tcpDialRefused.Load(),
        zapret2Stage.tcpDialUnreachable.Load(),
        zapret2Stage.tcpDialOther.Load(),
        zapret2Stage.tcpHelloSent.Load(),
        zapret2Stage.tcpHelloFailed.Load(),
        zapret2Stage.tcpFirstReply.Load(),
        zapret2Stage.tcpClosedNoReply.Load(),
        zapret2Stage.tcpFirstTLSAlert.Load(),
        zapret2Stage.tcpReadTimeout.Load(),
        zapret2Stage.udpInitialSent.Load(),
        zapret2Stage.udpInitialFailed.Load(),
        zapret2Stage.udpFirstReply.Load(),
        zapret2Stage.udpClosedNoReply.Load(),
    }
}

func isZapret2Timeout(err error) bool {
    if err == nil { return false }
    if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) { return true }
    var e net.Error
    return errors.As(err, &e) && e.Timeout()
}

func recordZapret2DialFailure(err error) {
    switch {
    case isZapret2Timeout(err):
        zapret2Stage.tcpDialTimeout.Add(1)
    case errors.Is(err, syscall.ECONNREFUSED):
        zapret2Stage.tcpDialRefused.Add(1)
    case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
        zapret2Stage.tcpDialUnreachable.Add(1)
    default:
        zapret2Stage.tcpDialOther.Add(1)
    }
}

// A TLS alert record visible on the very first server read. TLS1.3
// encrypted handshake records cannot establish an HTTPS response here.
func isTLSAlertRecordHeader(b []byte) bool {
    if len(b) < 5 || b[0] != 21 || b[1] != 3 || b[2] > 4 { return false }
    n := int(b[3])<<8 | int(b[4])
    return n >= 2 && n <= 16384
}
