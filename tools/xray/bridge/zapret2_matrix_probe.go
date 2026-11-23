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
    "errors"
    "io"
    "net"
    "net/http"
    "strconv"
    "strings"
    "sync"
    "time"

    quic "github.com/apernet/quic-go"
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
}

func parseMatrixTarget(id string) (matrixSpec, bool) {
    const prefix = "youtube_api_matrix_"
    if !strings.HasPrefix(id,prefix) { return matrixSpec{}, false }
    suffix:=strings.TrimPrefix(id,prefix)
    for provider:=range zapret2DoHProviders {
        if !strings.HasPrefix(suffix,provider+"_") {continue}
        rest:=strings.TrimPrefix(suffix,provider+"_")
        if rest=="prepare" {return matrixSpec{provider:provider,prepare:true},true}
        parts:=strings.Split(rest,"_")
        if len(parts)!=2 || len(parts[0])!=4 || !strings.HasPrefix(parts[0],"ip") {
            return matrixSpec{},false
        }
        n,err:=strconv.Atoi(parts[0][2:])
        if err!=nil || n<0 || n>=16 {return matrixSpec{},false}
        if parts[1]!="h1" && parts[1]!="h2" && parts[1]!="quic" {
            return matrixSpec{},false
        }
        return matrixSpec{provider:provider,index:n,protocol:parts[1]},true
    }
    return matrixSpec{},false
}

// A successful, explicitly requested prepare replaces the cache. Cache is
// bound to the active Xray instance and expires after ten minutes. The
// unredacted addresses live only in native memory, never in the report.
var matrixRRsets = struct {
    sync.Mutex
    instance *core.Instance
    expiry time.Time
    answers map[string]fixedDoHAnswer
}{}

func matrixPrepare(ctx context.Context, inst *core.Instance, provider string) fixedDoHAnswer {
    answer:=resolveFixedDoH(ctx,inst,provider)
    matrixRRsets.Lock()
    defer matrixRRsets.Unlock()
    if matrixRRsets.instance!=inst || time.Now().After(matrixRRsets.expiry) {
        matrixRRsets.answers=make(map[string]fixedDoHAnswer)
    }
    matrixRRsets.instance=inst
    matrixRRsets.expiry=time.Now().Add(10*time.Minute)
    delete(matrixRRsets.answers,provider)
    if answer.status=="ok" {matrixRRsets.answers[provider]=answer}
    return answer
}

func matrixPrepared(inst *core.Instance, provider string) (fixedDoHAnswer,bool) {
    matrixRRsets.Lock()
    defer matrixRRsets.Unlock()
    if matrixRRsets.instance!=inst || time.Now().After(matrixRRsets.expiry) {
        return fixedDoHAnswer{},false
    }
    answer,ok:=matrixRRsets.answers[provider]
    return answer,ok
}

// Only these validated strategy IDs are meaningful for TCP. QUIC is
// independent of TCP splitting and uses the plain private UDP outbound.
func matrixStrategyAllowed(strategy, protocol string) bool {
    if protocol=="quic" {return strategy=="plain"}
    return strategy=="plain" || strategy=="fake-5" || strategy=="tlsrec-split"
}

func matrixProbe(ctx context.Context, inst *core.Instance, strategy, targetID string,
    target zapret2TestTarget) Zapret2HTTPSResult {
    spec,ok:=parseMatrixTarget(targetID)
    out:=Zapret2HTTPSResult{Outcome:"invalid_target",DnsFingerprint:"-",
        Protocol:"dns",TLSStage:"none",ALPN:"-"}
    if !ok {return out}
    if spec.prepare {
        if strategy!="plain" {return out}
        answer:=matrixPrepare(ctx,inst,spec.provider)
        out.Outcome=answer.status
        if answer.status=="ok" {
            out.Outcome="dns_ready"
            out.DnsFingerprint=answer.fingerprint
            out.DnsAnswers=len(answer.ips)
        }
        out.HTTPStatus=answer.httpStatus
        return out
    }
    if !matrixStrategyAllowed(strategy,spec.protocol) {return out}
    out.Protocol=spec.protocol
    out.IPIndex=spec.index
    answer,ok:=matrixPrepared(inst,spec.provider)
    if !ok {out.Outcome="dns_not_prepared";return out}
    out.DnsFingerprint=answer.fingerprint
    out.DnsAnswers=len(answer.ips)
    if spec.index>=len(answer.ips) {out.Outcome="invalid_index";return out}
    ip:=answer.ips[spec.index] // never serialized
    network:=xnet.Network_TCP
    tag:=zapret2TestStrategies[strategy]+"-ipv4"
    if spec.protocol=="quic" {network=xnet.Network_UDP;tag=zapret2PlainTag+"-ipv4"}
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
    if spec.protocol=="quic" {
        return matrixWithMetadata(matrixQUIC(ctx,raw,ip),out)
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
}

func (c *matrixTLSConn) Write(b []byte) (int,error) {
    n,err:=c.Conn.Write(b)
    if n>=5 && b[0]==22 && b[1]==3 {c.helloWritten=true}
    return n,err
}
func (c *matrixTLSConn) Read(b []byte) (int,error) {
    n,err:=c.Conn.Read(b)
    if n>0 && !c.firstReply {
        c.firstReply=true
        c.firstAlert=isTLSAlertRecordHeader(b[:n])
    }
    return n,err
}
func (c *matrixTLSConn) phase() string {
    if c.firstReply {return "server_reply_seen"}
    if c.helloWritten {return "clienthello_sent"}
    return "tcp_connected"
}

func matrixHTTP(ctx context.Context,raw net.Conn,target zapret2TestTarget,proto string) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"tls_failed",TLSStage:"tcp_connected",ALPN:"-"}
    observed:=&matrixTLSConn{Conn:raw}
    alpns:=[]string{"http/1.1"}
    if proto=="h2" {alpns=[]string{"h2"}}
    tc:=tls.Client(observed,&tls.Config{
        ServerName:target.host,RootCAs:probeRoots,MinVersion:tls.VersionTLS12,NextProtos:alpns})
    defer tc.Close()
    if err:=tc.HandshakeContext(ctx);err!=nil {
        out.TLSStage=observed.phase()
        var authority x509.UnknownAuthorityError
        switch {
        case errors.As(err,&authority):out.Outcome="tls_ca_failed"
        case observed.firstAlert:out.Outcome="tls_alert"
        case ctx.Err()!=nil && !observed.firstReply:out.Outcome="timeout_tls_no_reply"
        case ctx.Err()!=nil:out.Outcome="timeout_tls_after_reply"
        }
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
    sent bool
    reply bool
}
func (p *matrixPacketConn) ReadFrom(b []byte) (int,net.Addr,error) {
    n,err:=p.Conn.Read(b)
    if n>0 {p.reply=true}
    return n,p.remote,err
}
func (p *matrixPacketConn) WriteTo(b []byte,addr net.Addr) (int,error) {
    if addr==nil || addr.String()!=p.remote.String() {
        return 0,errors.New("matrix UDP destination mismatch")
    }
    n,err:=p.Conn.Write(b)
    if n>0 {p.sent=true}
    return n,err
}
func (p *matrixPacketConn) LocalAddr() net.Addr {
    return &net.UDPAddr{IP:net.IPv4zero,Port:0}
}
func (p *matrixPacketConn) SetReadDeadline(t time.Time) error {return p.Conn.SetReadDeadline(t)}
func (p *matrixPacketConn) SetWriteDeadline(t time.Time) error {return p.Conn.SetWriteDeadline(t)}

func matrixQUIC(ctx context.Context,raw net.Conn,ip string) Zapret2HTTPSResult {
    out:=Zapret2HTTPSResult{Outcome:"quic_failed",TLSStage:"udp_connected",ALPN:"-"}
    remote:=&net.UDPAddr{IP:net.ParseIP(ip).To4(),Port:443}
    packets:=&matrixPacketConn{Conn:raw,remote:remote}
    cfg:=&tls.Config{ServerName:"youtubei.googleapis.com",RootCAs:probeRoots,
        MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}}
    conn,err:=quic.Dial(ctx,packets,remote,cfg,&quic.Config{})
    if err!=nil {
        if packets.reply {out.TLSStage="quic_peer_reply"}
        else if packets.sent {out.TLSStage="quic_initial_sent"}
        switch {
        case ctx.Err()!=nil && packets.reply:out.Outcome="quic_timeout_after_reply"
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
