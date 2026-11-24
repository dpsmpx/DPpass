//go:build linux

package bridge

import (
    "net"
    "sync"
    "golang.org/x/sys/unix"
)

// A bounded sample of real established TCP sockets, with no extra packets,
// no destination export, no timers and no dependency on connection logging.
// The registry is reset across Xray sessions. It never duplicates an fd.
const passiveQualityLimit = 32
var passiveQuality struct {
    sync.Mutex
    active bool
    generation uint64
    next int
    sockets [passiveQualityLimit]*net.TCPConn
}

func resetPassiveQuality(active bool) {
    passiveQuality.Lock()
    defer passiveQuality.Unlock()
    passiveQuality.active = active
    passiveQuality.generation++
    passiveQuality.next = 0
    passiveQuality.sockets = [passiveQualityLimit]*net.TCPConn{}
}

func passiveQualityGeneration() uint64 {
    passiveQuality.Lock()
    defer passiveQuality.Unlock()
    return passiveQuality.generation
}

func trackPassiveTCP(conn net.Conn, generation uint64) {
    tcp, ok := conn.(*net.TCPConn)
    if !ok { return }
    passiveQuality.Lock()
    defer passiveQuality.Unlock()
    if !passiveQuality.active || generation != passiveQuality.generation { return }
    passiveQuality.sockets[passiveQuality.next] = tcp
    passiveQuality.next = (passiveQuality.next + 1) % passiveQualityLimit
}

// PassiveQuality returns mean smoothed TCP RTT and mean kernel RTTVAR in
// microseconds. These measure the actual outbound TCP peer (a VPN server in
// a proxied session), not ICMP or end-to-end app latency. -1 means absent.
func PassiveQuality() (rtt, variation int64) {
    passiveQuality.Lock()
    sockets := passiveQuality.sockets
    generation := passiveQuality.generation
    active := passiveQuality.active
    passiveQuality.Unlock()
    if !active { return -1, -1 }
    var count int64
    for i, tcp := range sockets {
        if tcp == nil { continue }
        raw, err := tcp.SyscallConn()
        var info *unix.TCPInfo
        if err == nil {
            err = raw.Control(func(fd uintptr) {
                info, _ = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
            })
        }
        if err != nil || info == nil || info.State != 1 {
            passiveQuality.Lock()
            if passiveQuality.generation == generation && passiveQuality.sockets[i] == tcp {
                passiveQuality.sockets[i] = nil
            }
            passiveQuality.Unlock()
            continue
        }
        if info.Rtt == 0 { continue }
        rtt += int64(info.Rtt)
        variation += int64(info.Rttvar)
        count++
    }
    passiveQuality.Lock()
    unchanged := passiveQuality.generation == generation
    passiveQuality.Unlock()
    if count == 0 || !unchanged { return -1, -1 }
    return rtt/count, variation/count
}
