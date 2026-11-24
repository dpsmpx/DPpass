//go:build linux

package bridge

import ("net"; "testing")

func TestPassiveQualityUsesEstablishedSocketAndResets(t *testing.T) {
    resetPassiveQuality(true)
    defer resetPassiveQuality(false)
    if r,v := PassiveQuality(); r != -1 || v != -1 { t.Fatal(r,v) }
    listener,err := net.ListenTCP("tcp4", &net.TCPAddr{IP:net.IPv4(127,0,0,1)})
    if err != nil { t.Fatal(err) }
    defer listener.Close()
    conn,err := net.DialTCP("tcp4",nil,listener.Addr().(*net.TCPAddr))
    if err != nil { t.Fatal(err) }
    defer conn.Close()
    peer,err := listener.AcceptTCP()
    if err != nil { t.Fatal(err) }
    defer peer.Close()
    old := passiveQualityGeneration()
    trackPassiveTCP(conn, old)
    if r,v := PassiveQuality(); r <= 0 || v < 0 { t.Fatal("missing TCP_INFO",r,v) }
    resetPassiveQuality(true)
    trackPassiveTCP(conn,old)
    if r,v := PassiveQuality(); r != -1 || v != -1 { t.Fatal("stale socket",r,v) }
}
