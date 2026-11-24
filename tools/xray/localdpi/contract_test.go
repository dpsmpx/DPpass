package localdpi

import (
    "reflect"
    "testing"
)

func TestCapabilitiesExplicitAndOrdered(t *testing.T) {
    entries := []Support{{TLS,"pass"},{TLS,"split"},{QUIC,"pass"}}
    c,err:=NewCapabilities(VPNSocket,false,entries)
    if err!=nil { t.Fatal(err) }
    entries[0].MethodID="fake-3"
    if got:=c.Candidates(TLS);!reflect.DeepEqual(got,[]string{"split","pass"}) {
        t.Fatalf("candidate order or mutation: %v",got)
    }
    if c.Allows(TLS,"fake-3") || c.Allows(HTTP,"pass") {
        t.Fatal("executor advertised a method it did not register")
    }
    var zero Capabilities
    if zero.Allows(TLS,"pass") { t.Fatal("zero value must be unavailable") }
}

func TestCapabilitiesFailClosed(t *testing.T) {
    for _,tc:=range []struct{ kind ExecutorKind; root bool; entries []Support }{
        {0,true,nil},
        {RootSocket,false,[]Support{{TLS,"pass"}}},
        {RootPacket,false,[]Support{{TLS,"pass"}}},
        {VPNSocket,false,[]Support{{QUIC,"split"}}},
        {VPNSocket,false,[]Support{{TLS,"unknown"}}},
        {VPNSocket,false,[]Support{{TLS,"pass"},{TLS,"pass"}}},
    } {
        if _,err:=NewCapabilities(tc.kind,tc.root,tc.entries);err==nil {
            t.Fatalf("unexpected executor admission: %+v",tc)
        }
    }
    c,err:=NewCapabilities(RootPacket,true,nil)
    if err!=nil || len(c.Candidates(TLS))!=0 { t.Fatal("root consent must not imply method support") }
}

func TestFlowIdentityRejectsOldNetworkAndExecutor(t *testing.T) {
    vpn,err:=NewCapabilities(VPNSocket,false,[]Support{{TLS,"pass"}})
    if err!=nil { t.Fatal(err) }
    root,err:=NewCapabilities(RootSocket,true,[]Support{{TLS,"pass"}})
    if err!=nil { t.Fatal(err) }
    f:=FlowIdentity{VPNSocket,7,TLS,"pass"}
    if !f.Matches(vpn,7) || f.Matches(vpn,8) || f.Matches(root,7) {
        t.Fatal("network/executor isolation failed")
    }
    f.MethodID="split"
    if f.Matches(vpn,7) { t.Fatal("unsupported method accepted") }
}

func TestSocketEvidenceDoesNotClaimContent(t *testing.T) {
    for _,tc:=range []struct{ got Evidence; want Evidence }{
        {SocketClose(0),Evidence{Kind:Cancelled}},
        {SocketClose(-1),Evidence{Kind:Unknown}},
        {SocketClose(256),Evidence{Kind:Downstream,Bytes:256}},
        {SocketClose(1<<20),Evidence{Kind:Downstream,Bytes:1<<20}},
        {SocketFirstReplyTimeout(true,false,0),Evidence{Kind:FirstReplyTimeout}},
        {SocketFirstReplyTimeout(false,false,0),Evidence{Kind:Unknown}},
        {SocketFirstReplyTimeout(true,true,0),Evidence{Kind:Unknown}},
        {SocketFirstReplyTimeout(true,false,20),Evidence{Kind:Unknown}},
    } {
        if tc.got!=tc.want { t.Fatalf("got %+v want %+v",tc.got,tc.want) }
        if tc.got.Kind==VerifiedContent { t.Fatal("socket evidence promoted to content") }
    }
}
