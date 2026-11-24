//go:build linux

package bridge

// Opt-in, fixed-host address/protocol matrix. A preparation call obtains a
// certificate-verified DoH A RRset. Subsequent calls test a specific indexed
// IPv4 without re-resolving it through the configured or Android DNS.
// All network paths are fixed; no user URL, payload, credentials or IPs leave
// this Go process. No probe updates the live VPN route or AUTO training.
import (
    "bufio"
    "context"
    "crypto/tls"
    "crypto/x509"
    "encoding/binary"
    "encoding/json"
    "bytes"
    "errors"
    "io"
    "net"
    "syscall"
    "net/http"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
    "time"

    quic "github.com/apernet/quic-go"
    "github.com/apernet/quic-go/http3"
    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
    "golang.org/x/net/http2"
)

type matrixSpec struct {
    provider string
    index int
    protocol string
    prepare bool
    control bool
    h3test bool
}

// Probe identifiers are finite; no URL, remote host or raw IP can be passed
// from the UI to the native network layer.
func parseMatrixTarget(id string) (matrixSpec, bool) {
    if id=="youtube_api_h3_prepare" {
        return matrixSpec{provider:"google",prepare:true,h3test:true},true
    }
    if strings.HasPrefix(id,"youtube_api_h3_") {
        index,proto,ok:=parseMatrixIndexProtocol(strings.TrimPrefix(id,"youtube_api_h3_"),16)
        if !ok || (proto!="quic" && proto!="quicv2" && proto!="h3" && proto!="h3api") {return matrixSpec{},false}
        return matrixSpec{provider:"google",index:index,protocol:proto,h3test:true},true
    }
    if id=="google_control_prepare" {
        return matrixSpec{provider:"google",prepare:true,control:true},true
    }
    if strings.HasPrefix(id,"google_control_") {
        index,proto,ok:=parseMatrixIndexProtocol(strings.TrimPrefix(id,"google_control_"),2)
        if !ok || proto=="h3" || proto=="h3api" {return matrixSpec{},false}
        return matrixSpec{provider:"google",index:index,protocol:proto,control:true},true
    }
    const prefix="youtube_api_matrix_"
    if !strings.HasPrefix(id,prefix) {return matrixSpec{},false}
    suffix:=strings.TrimPrefix(id,prefix)
    for provider:=range zapret2DoHProviders {
        if !strings.HasPrefix(suffix,provider+"_") {continue}
        rest:=strings.TrimPrefix(suffix,provider+"_")
        if rest=="prepare" {return matrixSpec{provider:provider,prepare:true},true}
        index,proto,ok:=parseMatrixIndexProtocol(rest,16)
        if !ok || proto=="h3" || proto=="h3api" || proto=="quicv2" {return matrixSpec{},false}
        return matrixSpec{provider:provider,index:index,protocol:proto},true
    }
    return matrixSpec{},false
}
func parseMatrixIndexProtocol(rest string,limit int) (int,string,bool) {
    parts:=strings.Split(rest,"_")
    if len(parts)!=2 || len(parts[0])!=4 || !strings.HasPrefix(parts[0],"ip") {
        return 0,"",false
    }
    n,err:=strconv.Atoi(parts[0][2:])
    if err!=nil || n<0 || n>=limit {return 0,"",false}
    proto:=parts[1]
    if proto!="h1" && proto!="h2" && proto!="quic" && proto!="quicv2" && proto!="h3" && proto!="h3api" {return 0,"",false}
    return n,proto,true
}

// A successful, explicitly requested prepare replaces the cache. Cache is
// bound to the active Xray instance and expires after forty-five minutes. The
// unredacted addresses live only in native memory, never in the report.
var matrixRRsets = struct {
    sync.Mutex
    instance *core.Instance
    expiry time.Time
    answers map[string]fixedDoHAnswer
    h3Issued time.Time // five-minute experimental selection TTL
}{}

func matrixPrepare(ctx context.Context, inst *core.Instance, cacheKey, provider, question string) fixedDoHAnswer {
    answer:=resolveFixedDoHForQuestion(ctx,inst,provider,question)
    matrixRRsets.Lock()
    defer matrixRRsets.Unlock()
    if matrixRRsets.instance!=inst || time.Now().After(matrixRRsets.expiry) {
        matrixRRsets.answers=make(map[string]fixedDoHAnswer)
    }
    matrixRRsets.instance=inst
    matrixRRsets.expiry=time.Now().Add(45*time.Minute)
    delete(matrixRRsets.answers,cacheKey)
    if cacheKey=="youtube_api_h3" {matrixRRsets.h3Issued=time.Now()}
    if answer.status=="ok" {matrixRRsets.answers[cacheKey]=answer}
    return answer
}

func matrixPrepared(inst *core.Instance, provider string) (fixedDoHAnswer,bool) {
    matrixRRsets.Lock()
    defer matrixRRsets.Unlock()
    if matrixRRsets.instance!=inst || time.Now().After(matrixRRsets.expiry) {
        return fixedDoHAnswer{},false
    }
    if provider=="youtube_api_h3" && time.Since(matrixRRsets.h3Issued)>5*time.Minute {
        return fixedDoHAnswer{},false
    }
    answer,ok:=matrixRRsets.answers[provider]
    return answer,ok
}

// Only these validated strategy IDs are meaningful for TCP. QUIC is
// independent of TCP splitting and uses the plain private UDP outbound.
func matrixStrategyAllowed(strategy, protocol string) bool {
    if protocol=="quic" || protocol=="quicv2" || protocol=="h3" || protocol=="h3api" {return strategy=="plain"}
    if protocol!="h1" && protocol!="h2" {return false}
    return strategy=="plain" || strategy=="fake-5" || strategy=="tlsrec-split"
}

func matrixProbe(ctx context.Context, inst *core.Instance, strategy, targetID string,
    target zapret2TestTarget) Zapret2HTTPSResult {
    spec,ok:=parseMatrixTarget(targetID)
    out:=Zapret2HTTPSResult{Outcome:"invalid_target",DnsFingerprint:"-",
        Protocol:"dns",TLSStage:"none",ALPN:"-"}
    if !ok {return out}
    cacheKey:=spec.provider
    question:=zapret2DoHQuestion
    if spec.h3test {cacheKey="youtube_api_h3"}
    if spec.control {
        // Exactly the same protected private Xray TCP/UDP and per-socket
        // instrumentation, but a well-known control hostname and pinned
        // Google DoH A-answer set.
        cacheKey="google_control"
        question=zapret2ControlDoHQuestion
        target=zapret2TestTarget{host:"www.google.com",path:"/",
            contentKind:"http_transport",ipv4Only:true}
    }
    if spec.prepare {
        if strategy!="plain" {return out}
        answer:=matrixPrepare(ctx,inst,cacheKey,spec.provider,question)
        out.Outcome=answer.status
        if answer.status=="ok" {
            out.Outcome="dns_ready"
            out.DnsFingerprint=answer.fingerprint
            out.DnsAnswers=len(answer.ips)
        }
        out.HTTPStatus=answer.httpStatus
        return out
    }
    if !matrixStrategyAllowed(strategy,spec.protocol) || (spec.control && strategy!="plain") {return out}
    out.Protocol=spec.protocol
    out.IPIndex=spec.index
    answer,ok:=matrixPrepared(inst,cacheKey)
    if !ok {out.Outcome="dns_not_prepared";return out}
    out.DnsFingerprint=answer.fingerprint
    out.DnsAnswers=len(answer.ips)
    if spec.index>=len(answer.ips) {out.Outcome="invalid_index";return out}
    ip:=answer.ips[spec.index] // never serialized
    network:=xnet.Network_TCP
    tag:=zapret2TestStrategies[strategy]+"-ipv4"
    if spec.protocol=="quic" || spec.protocol=="quicv2" || spec.protocol=="h3" || spec.protocol=="h3api" {
        network=xnet.Network_UDP
        tag=zapret2PlainTag+"-ipv4"
    }
    dest:=xnet.Destination{Network:network,Address:xnet.ParseAddress(ip),Port:443}
    raw,err:=core.Dial(session.SetForcedOutboundTagToContext(ctx,tag),inst,dest)
    if err!=nil {
        out.Outcome="dial_failed"
        if ctx.Err()!=nil {out.Outcome="timeout_dial"}
        return out
    }
    defer raw.Close()
    done:=make(chan struct{})
    defer close(done)
    go func() {select {case <-ctx.Done():_=raw.Close();case <-done:}}()
    if spec.protocol=="quic" || spec.protocol=="quicv2" {
        version:=quic.Version1
        if spec.protocol=="quicv2" {version=quic.Version2}
        return matrixWithMetadata(matrixQUIC(ctx,raw,ip,target.host,version),out)
    }
    if spec.protocol=="h3" || spec.protocol=="h3api" {
        return matrixWithMetadata(matrixHTTP3(ctx,raw,ip,target.host,spec.protocol),out)
    }
    return matrixWithMetadata(matrixHTTP(ctx,raw,target,spec.protocol),out)
}

func matrixWithMetadata(result, parent Zapret2HTTPSResult) Zapret2HTTPSResult {
    result.DnsFingerprint=parent.DnsFingerprint
    result.DnsAnswers=parent.DnsAnswers
    result.Protocol=parent.Protocol
    result.IPIndex=parent.IPIndex
    if result.ALPN=="" {result.ALPN="-"}
    if result.TLSStage=="" {result.TLSStage="none"}
    return result
}

// Instrument the single probe socket, unlike process-wide Xray counters.
// The first write is ClientHello and the first read is a peer reply.
// This tells apart "no ServerHello bytes" and "some TLS reply" without
// assuming a successful handshake from the presence of bytes.
type matrixTLSConn struct {
    net.Conn
    helloWritten bool
    firstReply bool
    firstAlert bool
    serverHello bool
    replyPrefix []byte
}

func (c *matrixTLSConn) Write(b []byte) (int,error) {
    n,err:=c.Conn.Write(b)
    if n>=5 && b[0]==22 && b[1]==3 {c.helloWritten=true}
    return n,err
}
// ServerHello is an unencrypted TLS handshake message with type 2. Treat
// arbitrary first TLS bytes as only a peer reply; a ServerHello marker is
// not a verified certificate or completed TLS handshake.
func matrixHasServerHello(records []byte) bool {
    for i:=0;i+6<=len(records); {
        typ:=records[i]
        if records[i+1]!=3 || records[i+2]>4 {return false}
        size:=int(records[i+3])<<8|int(records[i+4])
        if size<1 || size>16384 {return false}
        if typ==22 && records[i+5]==2 {return true}
        if i+5+size>len(records) {return false}
        i+=5+size
    }
    return false
}
func (c *matrixTLSConn) Read(b []byte) (int,error) {
    n,err:=c.Conn.Read(b)
    if n>0 {
        if !c.firstReply {
            c.firstReply=true
            c.firstAlert=isTLSAlertRecordHeader(b[:n])
        }
        if !c.serverHello && len(c.replyPrefix)<8192 {
            count:=min(n,8192-len(c.replyPrefix))
            c.replyPrefix=append(c.replyPrefix,b[:count]...)
            c.serverHello=matrixHasServerHello(c.replyPrefix)
        }
    }
    return n,err
}
func (c *matrixTLSConn) phase() string {
    if c.serverHello {return "serverhello_seen"}
    if c.firstReply {return "server_reply_seen"}
    if c.helloWritten {return "clienthello_sent"}
    return "tcp_connected"
}

// Distinguish actual EOF/reset/closed-socket failures from missing peer
// replies that lasted until the deadline. Never serialize Go error strings,
// socket addresses, certificates, DNS answers or server response content.
func matrixTLSFailure(err error, ctx context.Context, observed *matrixTLSConn) string {
    var authority x509.UnknownAuthorityError
    if errors.As(err,&authority) {return "tls_ca_failed"}
    if observed.firstAlert {return "tls_alert"}
    suffix:="_no_reply"
    if observed.firstReply {suffix="_after_reply"}
    if ctx.Err()!=nil {return "timeout_tls"+suffix}
    if errors.Is(err,syscall.ECONNRESET) || errors.Is(err,syscall.EPIPE) {
        return "tls_reset"+suffix
    }
    if errors.Is(err,io.EOF) || errors.Is(err,io.ErrUnexpectedEOF) {
        return "tls_eof"+suffix
    }
    if errors.Is(err,net.ErrClosed) {return "tls_closed"+suffix}
    var netErr net.Error
    if errors.As(err,&netErr) && netErr.Timeout() {
        return "timeout_tls"+suffix
    }
    return "tls_failed"
}

func matrixHTTP(ctx context.Context,raw net.Conn,target zapret2TestTarget,proto string) Zapret2HTTPSResult {
    return matrixHTTPWithVersion(ctx,raw,target,proto,0)
}

// A nonzero forcedVersion narrows BOTH MinVersion and MaxVersion for a
// strictly opt-in, isolated API-versus-Google same-IP diagnostic. The
// existing production and matrix paths retain their default TLS range.
func matrixHTTPWithVersion(ctx context.Context,raw net.Conn,target zapret2TestTarget,
    proto string,forcedVersion uint16) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"tls_failed",TLSStage:"tcp_connected",ALPN:"-"}
    observed:=&matrixTLSConn{Conn:raw}
    alpns:=[]string{"http/1.1"}
    if proto=="h2" {alpns=[]string{"h2"}}
    tlsConfig:=&tls.Config{
        ServerName:target.host,RootCAs:probeRoots,MinVersion:tls.VersionTLS12,NextProtos:alpns}
    if forcedVersion!=0 {
        if forcedVersion!=tls.VersionTLS12 && forcedVersion!=tls.VersionTLS13 {
            out.Outcome="invalid_tls_version"
            return out
        }
        tlsConfig.MinVersion=forcedVersion
        tlsConfig.MaxVersion=forcedVersion
    }
    tc:=tls.Client(observed,tlsConfig)
    defer tc.Close()
    if err:=tc.HandshakeContext(ctx);err!=nil {
        out.TLSStage=observed.phase()
        out.Outcome=matrixTLSFailure(err,ctx,observed)
        return out
    }
    out.TLSStage="tls_verified"
    out.ALPN=tc.ConnectionState().NegotiatedProtocol
    if out.ALPN=="" {out.ALPN="-"}
    if proto=="h2" && out.ALPN!="h2" {
        out.Outcome="h2_not_negotiated"
        return out
    }
    req,err:=http.NewRequestWithContext(ctx,http.MethodGet,
        "https://"+target.host+target.path,nil)
    if err!=nil {out.Outcome="request_failed";return out}
    req.Header.Set("Accept","*/*")
    req.Header.Set("Accept-Encoding","identity")
    req.Close=true
    var resp *http.Response
    if proto=="h2" {
        client,err:=(&http2.Transport{}).NewClientConn(tc)
        if err!=nil {out.Outcome="h2_failed";return out}
        defer client.Close()
        resp,err=client.RoundTrip(req)
        if err!=nil {
            out.Outcome="http_failed"
            if ctx.Err()!=nil {out.Outcome="timeout_headers"}
            return out
        }
    } else {
        if err=req.Write(tc);err!=nil {
            out.Outcome="request_failed"
            if ctx.Err()!=nil {out.Outcome="timeout_write"}
            return out
        }
        resp,err=http.ReadResponse(bufio.NewReader(tc),req)
        if err!=nil {
            out.Outcome="http_failed"
            if ctx.Err()!=nil {out.Outcome="timeout_headers"}
            return out
        }
    }
    defer resp.Body.Close()
    out.HTTPStatus=resp.StatusCode
    // The endpoint is an unauthenticated API transport control. A small
    // bounded read is sufficient; response content is never emitted.
    body,readErr:=io.ReadAll(io.LimitReader(resp.Body,256))
    out.BodyBytes=int64(len(body))
    if ctx.Err()!=nil && readErr!=nil {out.Outcome="timeout_body";return out}
    out.Outcome=classifyProbeHTTP(resp.StatusCode,resp.Header.Get("Content-Type"),
        body,readErr,target)
    return out
}

// Xray core.Dial creates a protected, connected UDP transport. QUIC needs
// net.PacketConn; this adapter hard-binds writes to its original IPv4 peer,
// and does not create unprotected sockets or permit destination changes.
type matrixPacketConn struct {
    net.Conn
    remote *net.UDPAddr
    sent atomic.Bool
    reply atomic.Bool
    firstReplyHeader atomic.Int32
}

// Header classes describe only apparent public QUIC packet-header bytes.
// A matching header is not a verified server identity or completed handshake.
const (
    matrixPeerShortHeader int32 = iota + 1
    matrixPeerVersionNegotiation
    matrixPeerRetryHeader
    matrixPeerInitialHeader
    matrixPeerHandshakeHeader
    matrixPeerLongOther
    matrixPeerUnrecognized
)

func matrixPeerHeaderClass(datagram []byte) int32 {
    if len(datagram)==0 {return matrixPeerUnrecognized}
    if datagram[0]&0x80==0 {return matrixPeerShortHeader}
    if len(datagram)<5 {return matrixPeerUnrecognized}
    version:=binary.BigEndian.Uint32(datagram[1:5])
    if version==0 {return matrixPeerVersionNegotiation}
    // Check the fixed bit and the minimum long-header fields only.
    // No CID, payload, token, address or unencrypted bytes are exported.
    if datagram[0]&0x40==0 || len(datagram)<7 {
        return matrixPeerUnrecognized
    }
    packetType:=(datagram[0]>>4)&3
    switch version {
    case 1: // RFC 9000: Initial(0), 0-RTT(1), Handshake(2), Retry(3)
        switch packetType {
        case 0: return matrixPeerInitialHeader
        case 2: return matrixPeerHandshakeHeader
        case 3: return matrixPeerRetryHeader
        }
    case 0x6b3343cf: // RFC 9369 QUIC v2: Retry(0), Initial(1), Handshake(3)
        switch packetType {
        case 0: return matrixPeerRetryHeader
        case 1: return matrixPeerInitialHeader
        case 3: return matrixPeerHandshakeHeader
        }
    }
    return matrixPeerLongOther
}

func (p *matrixPacketConn) failureStage() string {
    if p.reply.Load() {
        switch p.firstReplyHeader.Load() {
        case matrixPeerShortHeader: return "quic_peer_short_header"
        case matrixPeerVersionNegotiation: return "quic_peer_vn_header"
        case matrixPeerRetryHeader: return "quic_peer_retry_header"
        case matrixPeerInitialHeader: return "quic_peer_initial_header"
        case matrixPeerHandshakeHeader: return "quic_peer_handshake_header"
        case matrixPeerLongOther: return "quic_peer_long_other"
        default: return "quic_peer_unrecognized"
        }
    }
    if p.sent.Load() {return "quic_initial_sent"}
    return "udp_connected"
}

func (p *matrixPacketConn) ReadFrom(b []byte) (int,net.Addr,error) {
    n,err:=p.Conn.Read(b)
    if n>0 {
        p.firstReplyHeader.CompareAndSwap(0,matrixPeerHeaderClass(b[:n]))
        p.reply.Store(true)
    }
    return n,p.remote,err
}
func (p *matrixPacketConn) WriteTo(b []byte,addr net.Addr) (int,error) {
    if addr==nil || addr.String()!=p.remote.String() {
        return 0,errors.New("matrix UDP destination mismatch")
    }
    n,err:=p.Conn.Write(b)
    if n>0 {p.sent.Store(true)}
    return n,err
}
func (p *matrixPacketConn) LocalAddr() net.Addr {
    return &net.UDPAddr{IP:net.IPv4zero,Port:0}
}
func (p *matrixPacketConn) SetReadDeadline(t time.Time) error {return p.Conn.SetReadDeadline(t)}
func (p *matrixPacketConn) SetWriteDeadline(t time.Time) error {return p.Conn.SetWriteDeadline(t)}

func matrixQUIC(ctx context.Context,raw net.Conn,ip,host string,version quic.Version) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"quic_failed",TLSStage:"udp_connected",ALPN:"-"}
    remote:=&net.UDPAddr{IP:net.ParseIP(ip).To4(),Port:443}
    packets:=&matrixPacketConn{Conn:raw,remote:remote}
    cfg:=&tls.Config{ServerName:host,RootCAs:probeRoots,
        MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}}
    conn,err:=quic.Dial(ctx,packets,remote,cfg,&quic.Config{Versions:[]quic.Version{version}})
    if err!=nil {
        out.TLSStage=packets.failureStage()
        switch {
        case ctx.Err()!=nil && packets.reply.Load():out.Outcome="quic_timeout_after_reply"
        case ctx.Err()!=nil:out.Outcome="quic_timeout_no_reply"
        default:out.Outcome="quic_failed"
        }
        return out
    }
    defer conn.CloseWithError(0,"probe completed")
    state:=conn.ConnectionState().TLS
    out.TLSStage="quic_tls_verified"
    out.ALPN=state.NegotiatedProtocol
    if out.ALPN!="h3" {out.Outcome="quic_alpn_mismatch";return out}
    out.Outcome="quic_verified" // handshake only; NOT HTTP/3 or a working feed
    return out
}

// Experimental HTTP/3 checks intentionally share exactly the same QUIC socket,
// pinned IPv4 peer and certificate-verified SNI as matrixQUIC. Neither the
// HTTP/3 transport nor net/http may open an additional UDP or DNS socket.
// A GET checks actual H3 HTTP transport; a fixed unauthenticated browse POST
// checks the application endpoint without credentials or personalized input.
const matrixH3BodyLimit = 8192
const matrixH3BrowseBody = `{"context":{"client":{"clientName":"WEB","clientVersion":"2.20261122.00.00","hl":"en","gl":"US"}},"browseId":"FEwhat_to_watch"}`

func matrixH3ClassifyAPI(code int,ctype string,body []byte,readErr error,overflow bool) string {
    if code>=400 && code<500 {return "h3_api_http_rejected"}
    if code<200 || code>=300 {return "http_status"}
    if !strings.HasPrefix(strings.ToLower(ctype),"application/json") {
        return "h3_api_content_type"
    }
    if readErr!=nil {return "h3_api_body_failed"}
    if len(body)==0 {return "h3_api_empty"}
    // Never label a truncated JSON body a verified YouTube feed.
    if overflow {return "h3_api_body_limit"}
    if !json.Valid(body) {return "h3_api_json_invalid"}
    return "h3_api_json_valid" // syntax only; not proof of usable feed
}

func matrixHTTP3(ctx context.Context,raw net.Conn,ip,host,mode string) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"h3_failed",TLSStage:"udp_connected",ALPN:"-"}
    if host!="youtubei.googleapis.com" || (mode!="h3" && mode!="h3api") {
        out.Outcome="invalid_target"
        return out
    }
    remote:=&net.UDPAddr{IP:net.ParseIP(ip).To4(),Port:443}
    packets:=&matrixPacketConn{Conn:raw,remote:remote}
    cfg:=&tls.Config{ServerName:host,RootCAs:probeRoots,
        MinVersion:tls.VersionTLS13,NextProtos:[]string{http3.NextProtoH3}}
    // Preserve the exact QUIC v1 protocol proven by the 3/3 admission gate.
    conn,err:=quic.Dial(ctx,packets,remote,cfg,&quic.Config{Versions:[]quic.Version{quic.Version1}})
    if err!=nil {
        out.TLSStage=packets.failureStage()
        switch {
        case ctx.Err()!=nil && packets.reply.Load():out.Outcome="quic_timeout_after_reply"
        case ctx.Err()!=nil:out.Outcome="quic_timeout_no_reply"
        default:out.Outcome="quic_failed"
        }
        return out
    }
    defer conn.CloseWithError(0,"experimental probe complete")
    out.TLSStage="quic_tls_verified"
    out.ALPN=conn.ConnectionState().TLS.NegotiatedProtocol
    if out.ALPN!="h3" {out.Outcome="quic_alpn_mismatch";return out}
    result:=matrixH3OnConnection(ctx,conn,host,mode)
    result.TLSStage=out.TLSStage
    result.ALPN=out.ALPN
    return result
}

// This helper is also exercised by a local, real QUIC/HTTP3 server test;
// it accepts only an already connected TLS-verified QUIC session. No Dial.
func matrixH3OnConnection(ctx context.Context,conn *quic.Conn,host,mode string) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"h3_failed",TLSStage:"quic_tls_verified",ALPN:"h3"}
    if host!="youtubei.googleapis.com" || (mode!="h3" && mode!="h3api") {
        out.Outcome="invalid_target"
        return out
    }
    tr:=&http3.Transport{}
    // NewClientConn reuses our already verified QUIC connection and never
    // invokes the transport's default network dialer.
    client:=tr.NewClientConn(conn)
    method:=http.MethodGet
    path:="/"
    var input io.Reader
    if mode=="h3api" {
        method=http.MethodPost
        path="/youtubei/v1/browse"
        input=bytes.NewReader([]byte(matrixH3BrowseBody))
    }
    req,err:=http.NewRequestWithContext(ctx,method,"https://"+host+path,input)
    if err!=nil {out.Outcome="request_failed";return out}
    req.Header.Set("Accept-Encoding","identity")
    req.Header.Set("Accept","application/json")
    if mode=="h3api" {
        req.Header.Set("Content-Type","application/json")
        req.Header.Set("X-YouTube-Client-Name","1")
        req.Header.Set("X-YouTube-Client-Version","2.20261122.00.00")
    }
    resp,err:=client.RoundTrip(req)
    if err!=nil {
        out.Outcome="h3_request_failed"
        if ctx.Err()!=nil {out.Outcome="h3_timeout_headers"}
        return out
    }
    defer resp.Body.Close()
    out.HTTPStatus=resp.StatusCode
    // Read a fixed-size bound only; the response is neither logged nor
    // returned to Android. No redirect is followed.
    body,readErr:=io.ReadAll(io.LimitReader(resp.Body,matrixH3BodyLimit+1))
    overflow:=len(body)>matrixH3BodyLimit
    if overflow {body=body[:matrixH3BodyLimit]}
    out.BodyBytes=int64(len(body))
    if ctx.Err()!=nil && readErr!=nil {
        out.Outcome="timeout_body"
        return out
    }
    if mode=="h3api" {
        out.Outcome=matrixH3ClassifyAPI(resp.StatusCode,
            resp.Header.Get("Content-Type"),body,readErr,overflow)
        return out
    }
    // Even a genuine h3 400/404 confirms H3 transport only, not content.
    if resp.StatusCode>=200 && resp.StatusCode<500 {
        out.Outcome="http_reachable"
    } else {out.Outcome="http_status"}
    return out
}

// Script H3 uses the very same protected, pinned UDP socket as the QUIC
// diagnostic. This does not open a second unprotected socket. The only
// permitted HTTP/3 target is the fixed unauthenticated YouTube API control.
func matrixH3Pinned(ctx context.Context, raw net.Conn, ip, host, mode string) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"h3_failed",TLSStage:"udp_connected",ALPN:"-"}
    if host!="youtubei.googleapis.com" || (mode!="h3" && mode!="h3api") {
        out.Outcome="invalid_target"
        return out
    }
    remote:=&net.UDPAddr{IP:net.ParseIP(ip).To4(),Port:443}
    packets:=&matrixPacketConn{Conn:raw,remote:remote}
    cfg:=&tls.Config{ServerName:host,RootCAs:probeRoots,
        MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}}
    conn,err:=quic.Dial(ctx,packets,remote,cfg,&quic.Config{
        Versions:[]quic.Version{quic.Version1},
    })
    if err!=nil {
        out.TLSStage=packets.failureStage()
        if ctx.Err()!=nil && packets.reply.Load() {
            out.Outcome="quic_timeout_after_reply"
        } else if ctx.Err()!=nil {
            out.Outcome="quic_timeout_no_reply"
        } else {
            out.Outcome="quic_failed"
        }
        return out
    }
    defer conn.CloseWithError(0,"diagnostic completed")
    if conn.ConnectionState().TLS.NegotiatedProtocol!="h3" {
        out.Outcome="quic_alpn_mismatch"
        out.TLSStage="quic_tls_verified"
        return out
    }
    return matrixH3OnConnection(ctx,conn,host,mode)
}
