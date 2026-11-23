//go:build linux

package bridge

import (
    "context"
    "encoding/binary"
    "net"
    "strings"
    "testing"
    "time"
)

func TestDoHRequestHasZeroIDAndFixedAQuestion(t *testing.T) {
    msg:=newFixedDoHQuestion()
    wire,err:=msg.Pack()
    if err!=nil {t.Fatal(err)}
    if binary.BigEndian.Uint16(wire[:2])!=0 {t.Fatal("RFC 8484 DNS ID must be zero")}
    if len(msg.Question)!=1 || msg.Question[0].Name!=zapret2DoHQuestion ||
        msg.Question[0].Qtype!=1 {t.Fatal("not the fixed allowlisted A query")}
}

func TestMatrixTargetsStrictlyAllowlisted(t *testing.T) {
    valid:=[]string{
        "youtube_api_matrix_cloudflare_prepare",
        "youtube_api_matrix_google_ip00_h1",
        "youtube_api_matrix_quad9_ip15_h2",
        "youtube_api_matrix_quad9_ip03_quic",
    }
    for _,id:=range valid {
        spec,ok:=parseMatrixTarget(id)
        if !ok || spec.provider=="" {t.Errorf("rejected fixed probe %q",id)}
    }
    invalid:=[]string{
        "", "youtube_api_matrix_unknown_prepare",
        "youtube_api_matrix_google_ip16_h1",
        "youtube_api_matrix_google_ip-1_h1",
        "youtube_api_matrix_google_ip1_h1",
        "youtube_api_matrix_google_ip00_http3",
        "youtube_api_matrix_cloudflare_ip00_h1/../evil",
        "youtube_api_matrix_google_ip00_h1_extra",
        "https://youtubei.googleapis.com",
    }
    for _,id:=range invalid {
        if _,ok:=parseMatrixTarget(id);ok {t.Errorf("accepted %q",id)}
    }
}

func TestMatrixStrategyAndTransportBoundaries(t *testing.T) {
    for _,p:=range []string{"h1","h2"} {
        for _,s:=range []string{"plain","fake-5","tlsrec-split"} {
            if !matrixStrategyAllowed(s,p) {t.Fatalf("%s/%s unexpectedly forbidden",p,s)}
        }
    }
    for _,s:=range []string{"fake-5","tlsrec-split","auto","split"} {
        if matrixStrategyAllowed(s,"quic") {t.Fatalf("QUIC must not inherit TCP split: %s",s)}
    }
    if !matrixStrategyAllowed("plain","quic") {t.Fatal("QUIC baseline missing")}
    if matrixStrategyAllowed("fake-5","h3") {t.Fatal("HTTP/3 is not tested")}
}

func TestMatrixV3WireContainsNoIPOrContent(t *testing.T) {
    r:=Zapret2HTTPSResult{
        Outcome:"timeout_tls_no_reply",Elapsed:5*time.Second,
        DnsFingerprint:"6f706c12",DnsAnswers:8,IPIndex:7,
        Protocol:"h2",TLSStage:"clienthello_sent",ALPN:"-",
    }
    actual:=string(r.Wire())
    expected:="v3\ttimeout_tls_no_reply\t0\t0\t5000\t0\t0\t6f706c12\t8\t7\th2\tclienthello_sent\t-"
    if actual!=expected {t.Fatalf("matrix wire got %q",actual)}
    if strings.Contains(actual,"youtubei") || strings.Contains(actual,"1.1.1.1") {
        t.Fatal("private DNS address or hostname escaped")
    }
}

func TestMatrixTLSNoReplyAfterClientHello(t *testing.T) {
    client,server:=net.Pipe()
    defer client.Close()
    defer server.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),90*time.Millisecond)
    defer cancel()
    gotHello:=make(chan bool,1)
    go func(){
        buf:=make([]byte,4096)
        n,err:=server.Read(buf)
        gotHello<-n>5 && err==nil && buf[0]==22
        <-ctx.Done()
    }()
    result:=matrixHTTP(ctx,client,zapret2TestTargets["youtube_api_ipv4"],"h1")
    if !<-gotHello {t.Fatal("ClientHello was not sent")}
    if result.Outcome!="timeout_tls_no_reply" || result.TLSStage!="clienthello_sent" {
        t.Fatalf("misclassified stalled TLS: %+v",result)
    }
}

func TestMatrixTLSAlertAfterClientHello(t *testing.T) {
    client,server:=net.Pipe()
    defer client.Close()
    defer server.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
    defer cancel()
    go func(){
        buf:=make([]byte,4096)
        _,_=server.Read(buf)
        _,_=server.Write([]byte{21,3,3,0,2,2,40}) // fatal handshake_failure
    }()
    result:=matrixHTTP(ctx,client,zapret2TestTargets["youtube_api_ipv4"],"h2")
    if result.Outcome!="tls_alert" || result.TLSStage!="server_reply_seen" {
        t.Fatalf("TLS alert not separated from stall: %+v",result)
    }
}

func TestMatrixConnectedUDPForbidsForeignDestination(t *testing.T) {
    client,server:=net.Pipe()
    defer client.Close()
    defer server.Close()
    p:=&matrixPacketConn{Conn:client,remote:&net.UDPAddr{IP:net.IPv4(8,8,8,8),Port:443}}
    if _,err:=p.WriteTo([]byte{1},&net.UDPAddr{IP:net.IPv4(9,9,9,9),Port:443});err==nil {
        t.Fatal("packet adapter allowed foreign endpoint")
    }
    if p.sent.Load() {t.Fatal("blocked packet was sent")}
    if p.LocalAddr()==nil {t.Fatal("packet adapter missing local UDP address")}
}

func TestMatrixRecognizesServerHelloRecordNotJustPeerBytes(t *testing.T) {
    hello:=[]byte{22,3,3,0,4,2,0,0,0}
    alert:=[]byte{21,3,3,0,2,2,40}
    clientHello:=[]byte{22,3,3,0,4,1,0,0,0}
    if !matrixHasServerHello(hello) {t.Fatal("missed ServerHello")}
    for _,bad:=range [][]byte{hello[:5],alert,clientHello} {
        if matrixHasServerHello(bad) {t.Fatalf("false positive for %v",bad)}
    }
    ccs:=[]byte{20,3,3,0,1,1}
    if !matrixHasServerHello(append(ccs,hello...)) {
        t.Fatal("missed ServerHello after TLS 1.3 CCS")
    }
    client,server:=net.Pipe()
    defer client.Close()
    defer server.Close()
    observed:=&matrixTLSConn{Conn:client}
    go func(){
        _,_=server.Write(hello[:3])
        _,_=server.Write(hello[3:])
    }()
    buf:=make([]byte,16)
    _,_=observed.Read(buf)
    _,_=observed.Read(buf)
    if observed.phase()!="serverhello_seen" {
        t.Fatalf("split TLS record was misclassified: %s",observed.phase())
    }
}
