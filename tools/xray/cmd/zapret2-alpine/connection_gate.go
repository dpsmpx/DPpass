//go:build linux

package main

import "net"

// A fixed per-process admission limit bounds active sockets, goroutines
// and per-request frame allocation. The accept loop never queues work in
// user space. An overloaded socket is closed, not retried as direct traffic.
// The initial ceiling is provisional until Android load tests.
const maxPlannerConnections = 128

type connectionGate struct {
    slots chan struct{}
}

func newConnectionGate(limit int) *connectionGate {
    return &connectionGate{slots:make(chan struct{},limit)}
}

// start takes ownership of c even on refusal. Only admitted connections
// allocate a worker. The slot is released after the socket closes.
func (g *connectionGate) start(c net.Conn, handle func(net.Conn)) bool {
    select {
    case g.slots <- struct{}{}:
        go func(){
            defer func(){<-g.slots}()
            defer c.Close()
            handle(c)
        }()
        return true
    default:
        _ = c.Close()
        return false
    }
}
