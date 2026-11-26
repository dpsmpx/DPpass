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
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

type zapret2StageCounters struct {
    tcpDialOK atomic.Int64
    tcpDialTimeout atomic.Int64
    tcpDialRefused atomic.Int64
    tcpDialUnreachable atomic.Int64
    tcpDialOther atomic.Int64
    // Address-family observations: classify the actual remote socket when
    // connected, and the failed dial address when available. Unknown means
    // Xray/dialer did not expose an IP family (not assumed IPv4 or IPv6).
    tcpDialOKV4 atomic.Int64
    tcpDialOKV6 atomic.Int64
    tcpDialOKUnknown atomic.Int64
    tcpDialUnreachableV4 atomic.Int64
    tcpDialUnreachableV6 atomic.Int64
    tcpDialUnreachableUnknown atomic.Int64
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

var zapret2Stage zapret2StageCounters
var diagnosticStage zapret2StageCounters

func stagesFor(diagnostic bool) *zapret2StageCounters {
    if diagnostic {return &diagnosticStage}
    return &zapret2Stage
}

// Zapret2Stages v3: first fifteen values keep their original indexes,
// then six address-family counters and two native TLS plan counters.
// Live counters exclude tagged diagnostic adapters, including native
// in-process TLS encoder plans. DNS/DoH and app outcomes remain unknown.
// Per-family OK and unreachable totals must match corresponding aggregate
// totals except traffic from older libraries (the entire process shares one).
func Zapret2Stages() [23]int64 {
    encoded,fallback:=zapret2.NativeTLSRecordStats()
    return [23]int64{
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
        zapret2Stage.tcpDialOKV4.Load(),
        zapret2Stage.tcpDialOKV6.Load(),
        zapret2Stage.tcpDialOKUnknown.Load(),
        zapret2Stage.tcpDialUnreachableV4.Load(),
        zapret2Stage.tcpDialUnreachableV6.Load(),
        zapret2Stage.tcpDialUnreachableUnknown.Load(),
        encoded,
        fallback,
    }
}

func isZapret2Timeout(err error) bool {
    if err == nil { return false }
    if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, syscall.ETIMEDOUT) { return true }
    var e net.Error
    return errors.As(err, &e) && e.Timeout()
}

// Family 4/6 can only be determined from a known destination IP;
// nil is deliberately tracked as unknown instead of guessing.
func zapret2AddressFamily(ip net.IP) int {
    if ip == nil { return 0 }
    if ip.To4() != nil { return 4 }
    if ip.To16() != nil { return 6 }
    return 0
}

func recordZapret2DialSuccessFamily(ip net.IP) {
    zapret2Stage.recordDialSuccessFamily(ip)
}

func (s *zapret2StageCounters) recordDialSuccessFamily(ip net.IP) {
    switch zapret2AddressFamily(ip) {
    case 4: s.tcpDialOKV4.Add(1)
    case 6: s.tcpDialOKV6.Add(1)
    default: s.tcpDialOKUnknown.Add(1)
    }
}

func recordZapret2DialFailure(err error) { recordZapret2DialFailureWithIP(err, nil) }

func recordZapret2DialFailureWithIP(err error, ip net.IP) {
    zapret2Stage.recordDialFailure(err,ip)
}

func (s *zapret2StageCounters) recordDialFailure(err error, ip net.IP) {
    switch {
    case isZapret2Timeout(err):
        s.tcpDialTimeout.Add(1)
    case errors.Is(err, syscall.ECONNREFUSED):
        s.tcpDialRefused.Add(1)
    case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH):
        s.tcpDialUnreachable.Add(1)
        // If the error carries a concrete remote address, trust it instead
        // of the (possibly unresolved) Xray destination. Do not log the IP.
        var opErr *net.OpError
        if errors.As(err, &opErr) && opErr.Addr != nil {
            if tcp, ok := opErr.Addr.(*net.TCPAddr); ok && tcp.IP != nil {
                ip = tcp.IP
            }
        }
        switch zapret2AddressFamily(ip) {
        case 4: s.tcpDialUnreachableV4.Add(1)
        case 6: s.tcpDialUnreachableV6.Add(1)
        default: s.tcpDialUnreachableUnknown.Add(1)
        }
    default:
        s.tcpDialOther.Add(1)
    }
}

// A TLS alert record visible on the very first server read. TLS1.3
// encrypted handshake records cannot establish an HTTPS response here.
func isTLSAlertRecordHeader(b []byte) bool {
    if len(b) < 5 || b[0] != 21 || b[1] != 3 || b[2] > 4 { return false }
    n := int(b[3])<<8 | int(b[4])
    return n >= 2 && n <= 16384
}
