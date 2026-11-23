//go:build linux

package bridge

import (
    "context"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "math/big"
    "net/http"
    "encoding/binary"
    "errors"
    "io"
    "net"
    "syscall"
    "strings"
    "testing"
    "time"

    quic "github.com/apernet/quic-go"
    "github.com/apernet/quic-go/http3"
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

func TestMatrixGoogleControlAllowlistAndFixedProtocol(t *testing.T) {
    for _,id:=range []string{
        "google_control_prepare","google_control_ip00_h1",
        "google_control_ip01_h2","google_control_ip01_quic",
    } {
        spec,ok:=parseMatrixTarget(id)
        if !ok || !spec.control || spec.provider!="google" {
            t.Fatalf("fixed Google control rejected: %s %+v",id,spec)
        }
    }
    for _,id:=range []string{
        "google_control_ip02_h1","google_control_ip-1_h1",
        "google_control_ip0_h1","google_control_ip00_h3",
        "google_control_youtube_api_matrix_google_ip00_h1",
        "google_control_ip01_quic_https://bad.test",
    } {
        if _,ok:=parseMatrixTarget(id);ok {t.Fatalf("unsafe control accepted: %s",id)}
    }
    for _,id:=range []string{
        "google_control_prepare", "google_control_ip00_h1", "google_control_ip01_quic",
    } {
        got:=ProbeZapret2HTTPS("fake-9",id,2*time.Second)
        if got.Outcome!="invalid_strategy" {t.Fatalf("unapproved strategy accepted: %s",id)}
    }
}

func TestMatrixTLSCloseResetAndTimeoutAreDistinct(t *testing.T) {
    ctx:=context.Background()
    cases:=[]struct{err error; reply bool; want string}{
        {io.EOF,false,"tls_eof_no_reply"},
        {io.EOF,true,"tls_eof_after_reply"},
        {io.ErrUnexpectedEOF,false,"tls_eof_no_reply"},
        {syscall.ECONNRESET,false,"tls_reset_no_reply"},
        {syscall.ECONNRESET,true,"tls_reset_after_reply"},
        {net.ErrClosed,false,"tls_closed_no_reply"},
        {net.ErrClosed,true,"tls_closed_after_reply"},
        {errors.New("unrecognized transport"),false,"tls_failed"},
    }
    for _,tc:=range cases {
        obs:=&matrixTLSConn{firstReply:tc.reply}
        if got:=matrixTLSFailure(tc.err,ctx,obs);got!=tc.want {
            t.Errorf("error %s reply=%v got=%s want=%s",tc.err,tc.reply,got,tc.want)
        }
    }
    canceled,cancel:=context.WithCancel(context.Background())
    cancel()
    obs:=&matrixTLSConn{helloWritten:true}
    if got:=matrixTLSFailure(io.EOF,canceled,obs);got!="timeout_tls_no_reply" {
        t.Fatalf("timeout must override cancellation-induced EOF: %s",got)
    }
}

func TestMatrixTLSUnexpectedEOFObservedFromLivePipe(t *testing.T) {
    client,server:=net.Pipe()
    defer client.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),time.Second)
    defer cancel()
    go func(){
        b:=make([]byte,4096)
        _,_=server.Read(b) // consume ClientHello before EOF
        _=server.Close()
    }()
    got:=matrixHTTP(ctx,client,zapret2TestTargets["youtube_api_ipv4"],"h1")
    if got.Outcome!="tls_eof_no_reply" || got.TLSStage!="clienthello_sent" {
        t.Fatalf("live EOF should not be timeout: %+v",got)
    }
}

func TestYouTubeH3TargetsCannotEscapeFixedIPv4OrProtocols(t *testing.T) {
    for _,id:=range []string{
        "youtube_api_h3_prepare","youtube_api_h3_ip03_quic",
        "youtube_api_h3_ip00_h3","youtube_api_h3_ip15_h3api",
    } {
        spec,ok:=parseMatrixTarget(id)
        if !ok || !spec.h3test || spec.provider!="google" {
            t.Fatalf("rejected fixed H3 target %s: %+v",id,spec)
        }
    }
    for _,id:=range []string{
        "youtube_api_h3_ip16_quic","youtube_api_h3_ip-1_h3",
        "youtube_api_h3_ip3_h3","youtube_api_h3_ip03_http3",
        "youtube_api_h3_ip03_h3_extra","youtube_api_h3_ip03_h1",
        "youtube_api_matrix_google_ip03_h3",
        "google_control_ip00_h3api",
        "youtube_api_h3_ip00_h3/../../other",
    } {
        if _,ok:=parseMatrixTarget(id);ok {t.Fatalf("accepted unallowlisted %s",id)}
    }
    if matrixStrategyAllowed("fake-5","h3") ||
        matrixStrategyAllowed("tlsrec-split","h3api") {
        t.Fatal("HTTP3 must bypass TCP strategy tags")
    }
    if !matrixStrategyAllowed("plain","h3") ||
        !matrixStrategyAllowed("plain","h3api") {t.Fatal("plain H3 control missing")}
    if got:=ProbeZapret2HTTPS("plain","youtube_api_h3_ip16_h3",8*time.Second);
        got.Outcome!="invalid_target" {t.Fatalf("unapproved index: %+v",got)}
}

func TestH3AnonymousAPIClassificationNeverClaimsLargeJSONIsVerified(t *testing.T) {
    cases:=[]struct{
        code int
        ctype string
        body string
        overflow bool
        want string
    }{
        {200,"application/json; charset=UTF-8",`{"contents":[]}`,false,"h3_api_json_valid"},
        {200,"application/json",`{"contents":`,false,"h3_api_json_invalid"},
        {200,"application/json",`{"contents":`,true,"h3_api_body_limit"},
        {401,"application/json",`{"error":"authentication required"}`,false,"h3_api_http_rejected"},
        {403,"application/json","",false,"h3_api_http_rejected"},
        {200,"text/html","<html>",false,"h3_api_content_type"},
        {500,"application/json","{}",false,"http_status"},
        {200,"application/json","",false,"h3_api_empty"},
    }
    for _,tc:=range cases {
        got:=matrixH3ClassifyAPI(tc.code,tc.ctype,[]byte(tc.body),nil,tc.overflow)
        if got!=tc.want {t.Errorf("http=%d body=%q got=%s want=%s",tc.code,tc.body,got,tc.want)}
    }
    if got:=matrixH3ClassifyAPI(200,"application/json",[]byte("{}"),
        io.ErrUnexpectedEOF,false);got!="h3_api_body_failed" {
        t.Fatalf("partial JSON read must not be accepted: %s",got)
    }
}

func TestH3RealGETAndAnonymousBrowsePOSTOnLocalQUIC(t *testing.T) {
    // Network-free integration: local UDP packets only. This proves that
    // http3.NewClientConn sends HEADERS / DATA on the EXACT QUIC socket
    // supplied to it, with validated TLS and ALPN h3. No internet or
    // unprotected resolver access is required.
    key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil {t.Fatal(err)}
    now:=time.Now()
    tpl:=&x509.Certificate{
        SerialNumber:big.NewInt(1234),DNSNames:[]string{"youtubei.googleapis.com"},
        NotBefore:now.Add(-time.Hour),NotAfter:now.Add(time.Hour),
        KeyUsage:x509.KeyUsageDigitalSignature,
        ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    der,err:=x509.CreateCertificate(rand.Reader,tpl,tpl,&key.PublicKey,key)
    if err!=nil {t.Fatal(err)}
    parsed,err:=x509.ParseCertificate(der)
    if err!=nil {t.Fatal(err)}
    roots:=x509.NewCertPool()
    roots.AddCert(parsed)
    cert:=tls.Certificate{Certificate:[][]byte{der},PrivateKey:key}
    methodSeen:=make(chan string,4)
    server:=&http3.Server{
        TLSConfig:&tls.Config{Certificates:[]tls.Certificate{cert},
            NextProtos:[]string{http3.NextProtoH3}},
        Handler:http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
            methodSeen<-r.Method+" "+r.URL.Path
            if r.Method==http.MethodPost {
                if r.URL.Path!="/youtubei/v1/browse" ||
                    r.Header.Get("Content-Type")!="application/json" {
                    w.WriteHeader(http.StatusBadRequest);return
                }
                w.Header().Set("Content-Type","application/json")
                _,_=w.Write([]byte(`{"contents":[],"responseContext":{}}`))
                return
            }
            if r.URL.Path!="/" {w.WriteHeader(404);return}
            w.WriteHeader(http.StatusNoContent)
        }),
    }
    udp,err:=net.ListenPacket("udp","127.0.0.1:0")
    if err!=nil {t.Fatal(err)}
    defer udp.Close()
    go func(){_=server.Serve(udp)}()
    defer server.Close()
    for _,tc:=range []struct{mode,want string}{
        {"h3","http_reachable"},
        {"h3api","h3_api_json_valid"},
    } {
        ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second)
        clientPacket,err:=net.ListenPacket("udp","127.0.0.1:0")
        if err!=nil {cancel();t.Fatal(err)}
        tlsConf:=&tls.Config{ServerName:"youtubei.googleapis.com",
            RootCAs:roots,MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}}
        conn,err:=quic.Dial(ctx,clientPacket,udp.LocalAddr(),tlsConf,&quic.Config{})
        if err!=nil {clientPacket.Close();cancel();t.Fatal(err)}
        if conn.ConnectionState().TLS.NegotiatedProtocol!="h3" {
            t.Fatal("HTTP/3 ALPN not negotiated")
        }
        result:=matrixH3OnConnection(ctx,conn,"youtubei.googleapis.com",tc.mode)
        _=conn.CloseWithError(0,"test finished")
        _=clientPacket.Close()
        cancel()
        if result.Outcome!=tc.want || result.TLSStage!="quic_tls_verified" {
            t.Fatalf("HTTP3 mode=%s outcome %+v",tc.mode,result)
        }
    }
    seen1,seen2:=<-methodSeen,<-methodSeen
    if seen1!="GET /" || seen2!="POST /youtubei/v1/browse" {
        t.Fatalf("H3 server did not receive expected HTTP requests: %s / %s",seen1,seen2)
    }
}


func TestMatrixQUICHeaderClassificationDoesNotAssumeTLSCompletion(t *testing.T) {
    // Public QUIC header shapes only; neither CID, token nor encrypted
    // payload is interpreted or exported to Android.
    cases:=[]struct{
        name string
        packet []byte
        want int32
        stage string
    }{
        {"v1_initial",[]byte{0xc0,0,0,0,1,0,0},matrixPeerInitialHeader,"quic_peer_initial_header"},
        {"v1_handshake",[]byte{0xe0,0,0,0,1,0,0},matrixPeerHandshakeHeader,"quic_peer_handshake_header"},
        {"v1_retry",[]byte{0xf0,0,0,0,1,0,0},matrixPeerRetryHeader,"quic_peer_retry_header"},
        {"version_negotiation",[]byte{0x80,0,0,0,0},matrixPeerVersionNegotiation,"quic_peer_vn_header"},
        {"v2_initial",[]byte{0xd0,0x6b,0x33,0x43,0xcf,0,0},matrixPeerInitialHeader,"quic_peer_initial_header"},
        {"v2_retry",[]byte{0xc0,0x6b,0x33,0x43,0xcf,0,0},matrixPeerRetryHeader,"quic_peer_retry_header"},
        {"v2_handshake",[]byte{0xf0,0x6b,0x33,0x43,0xcf,0,0},matrixPeerHandshakeHeader,"quic_peer_handshake_header"},
        {"other_version",[]byte{0xc0,1,2,3,4,0,0},matrixPeerLongOther,"quic_peer_long_other"},
        {"short_header",[]byte{0x40,1,2,3},matrixPeerShortHeader,"quic_peer_short_header"},
        {"malformed_long",[]byte{0x80,0,0},matrixPeerUnrecognized,"quic_peer_unrecognized"},
        {"invalid_fixed_bit",[]byte{0x80,0,0,0,1,0,0},matrixPeerUnrecognized,"quic_peer_unrecognized"},
    }
    for _,tc:=range cases {
        t.Run(tc.name,func(t *testing.T){
            if got:=matrixPeerHeaderClass(tc.packet);got!=tc.want {
                t.Fatalf("packet class got=%d want=%d",got,tc.want)
            }
            client,server:=net.Pipe()
            defer client.Close()
            defer server.Close()
            p:=&matrixPacketConn{Conn:client,remote:&net.UDPAddr{IP:net.IPv4(8,8,8,8),Port:443}}
            go func(){_,_=server.Write(tc.packet)}()
            buf:=make([]byte,100)
            n,_,err:=p.ReadFrom(buf)
            if err!=nil || n!=len(tc.packet) {t.Fatalf("read n=%d err=%v",n,err)}
            if !p.reply.Load() || p.failureStage()!=tc.stage {
                t.Fatalf("stage=%q reply=%v",p.failureStage(),p.reply.Load())
            }
            if p.sent.Load() {t.Fatal("response must not imply outbound write")}
        })
    }
}
