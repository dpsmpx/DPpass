//go:build linux

package bridge

import (
    "errors"
    "net"
    "sync"
    "syscall"
    "time"
)

// Suppress only repeated, explicit ENETUNREACH on literal IPv6 dials.
// Do not treat timeout, host failure, refusal or TLS errors as a missing
// route. One new real attempt is allowed after a short cooldown.
// Generation changes clear this temporary state.
type ipv6Backoff struct {
    mu sync.Mutex
    generation uint64
    failures int
    until time.Time
}
var liveIPv6 ipv6Backoff

func isIPv6Peer(ip net.IP) bool { return ip != nil && ip.To4() == nil && ip.To16() != nil }
func (b *ipv6Backoff) resetIfChanged(g uint64) {
    if b.generation != g { b.generation = g; b.failures = 0; b.until = time.Time{} }
}
func (b *ipv6Backoff) skip(ip net.IP, g uint64, now time.Time) bool {
    if !isIPv6Peer(ip) { return false }
    b.mu.Lock()
    defer b.mu.Unlock()
    b.resetIfChanged(g)
    return now.Before(b.until)
}
func (b *ipv6Backoff) result(ip net.IP, g uint64, now time.Time, err error) {
    if !isIPv6Peer(ip) { return }
    b.mu.Lock()
    defer b.mu.Unlock()
    // Ignore completion from an old session/network.
    if b.generation != g { return }
    if err == nil { b.failures = 0; b.until = time.Time{}; return }
    if !errors.Is(err, syscall.ENETUNREACH) { return }
    b.failures++
    if b.failures >= 2 { b.until = now.Add(15*time.Second); b.failures = 1 }
}
