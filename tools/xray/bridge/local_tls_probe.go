//go:build linux

package bridge

import (
    "bytes"
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/tls"
    "crypto/x509"
    "io"
    "math/big"
    "net"
    "time"

    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

const localTLSName = "example.com"
const localTLSALPN = "dppass-local-test"

func localTLSCertificate(now time.Time) (tls.Certificate,*x509.CertPool,error) {
    key,err:=ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
    if err!=nil {return tls.Certificate{},nil,err}
    template:=&x509.Certificate{
        SerialNumber:big.NewInt(1), DNSNames:[]string{localTLSName},
        NotBefore:now.Add(-time.Minute),NotAfter:now.Add(time.Hour),
        KeyUsage:x509.KeyUsageDigitalSignature|x509.KeyUsageCertSign,
        ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
        BasicConstraintsValid:true,IsCA:true,
    }
    der,err:=x509.CreateCertificate(rand.Reader,template,template,&key.PublicKey,key)
    if err!=nil {return tls.Certificate{},nil,err}
    leaf,err:=x509.ParseCertificate(der)
    if err!=nil {return tls.Certificate{},nil,err}
    roots:=x509.NewCertPool()
    roots.AddCert(leaf)
    return tls.Certificate{Certificate:[][]byte{der},PrivateKey:key,Leaf:leaf},roots,nil
}

// Fixed local fixture; no external name resolution, certificate installation,
// user payload, adaptive selection or application replay.
func probeLocalTLS(method,target string,timeout time.Duration) Zapret2HTTPSResult {
    started:=time.Now()
    out:=Zapret2HTTPSResult{Outcome:"invalid_strategy"}
    var mode desyncKind
    switch method {
    case "plain":
    case "multisplit":mode=desyncMultiSplit
    case "tlsrec-split":mode=desyncTLSRecordSplit
    case "tlsrec-chain":mode=desyncTLSRecordChain
    default:return out
    }
    var version uint16
    switch target {
    case "local_tls12":version=tls.VersionTLS12
    case "local_tls13":version=tls.VersionTLS13
    default:out.Outcome="invalid_target";return out
    }
    if timeout<time.Second || timeout>5*time.Second {
        out.Outcome="invalid_timeout"
        return out
    }
    counters:=&diagnosticRequestCounters{}
    finish:=func(outcome string) Zapret2HTTPSResult {
        out.Outcome=outcome
        return finalizeHTTPSDiagnostic(out,time.Since(started),counters)
    }
    deadline:=started.Add(timeout)
    cert,roots,err:=localTLSCertificate(started)
    if err!=nil {return finish("local_tls_mismatch")}
    listener,err:=net.ListenTCP("tcp4",&net.TCPAddr{IP:net.IPv4(127,0,0,1)})
    if err!=nil {return finish("dial_failed")}
    defer listener.Close()
    if err:=listener.SetDeadline(deadline);err!=nil {return finish("dial_failed")}
    dialer:=net.Dialer{Deadline:deadline}
    raw,err:=dialer.Dial("tcp4",listener.Addr().String())
    if err!=nil {return finish("dial_failed")}
    defer raw.Close()
    client,ok:=raw.(*net.TCPConn)
    if !ok {return finish("local_tls_mismatch")}
    server,err:=listener.AcceptTCP()
    if err!=nil {return finish("dial_failed")}
    defer server.Close()
    if client.SetDeadline(deadline)!=nil || server.SetDeadline(deadline)!=nil {
        return finish("dial_failed")
    }
    if !client.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() ||
        !server.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
        return finish("local_tls_mismatch")
    }
    var transport net.Conn=client
    if method!="plain" {
        wrapped:=&desyncConn{TCPConn:client,mode:desyncMode{kind:mode},diagnostic:true,request:counters,localTLSFixture:true}
        defer wrapped.Close()
        transport=wrapped
    }
    request:=[]byte("DPpass local TLS request")
    reply:=[]byte("DPpass local TLS reply")
    done:=make(chan struct{})
    serverOK:=false
    go func(){
        defer close(done)
        peer:=tls.Server(server,&tls.Config{Certificates:[]tls.Certificate{cert},
            MinVersion:version,MaxVersion:version,NextProtos:[]string{localTLSALPN}})
        if peer.Handshake()!=nil {return}
        state:=peer.ConnectionState()
        if !state.HandshakeComplete || state.Version!=version ||
            state.NegotiatedProtocol!=localTLSALPN || state.ServerName!=localTLSName {return}
        got:=make([]byte,len(request))
        if _,err:=io.ReadFull(peer,got);err!=nil || !bytes.Equal(got,request) {return}
        n,err:=peer.Write(reply)
        serverOK=err==nil && n==len(reply)
    }()
    defer func(){_ = server.Close();<-done}()
    observed:=&localTLSReadPrefix{Conn:transport}
    peer:=tls.Client(observed,&tls.Config{RootCAs:roots,ServerName:localTLSName,
        MinVersion:version,MaxVersion:version,NextProtos:[]string{localTLSALPN}})
    if peer.Handshake()!=nil || !observed.verified() {return finish("local_tls_mismatch")}
    state:=peer.ConnectionState()
    if !state.HandshakeComplete || state.Version!=version ||
        state.NegotiatedProtocol!=localTLSALPN || len(state.VerifiedChains)==0 {
        return finish("local_tls_mismatch")
    }
    if n,err:=peer.Write(request);err!=nil || n!=len(request) {return finish("local_tls_mismatch")}
    got:=make([]byte,len(reply))
    if _,err:=io.ReadFull(peer,got);err!=nil || !bytes.Equal(got,reply) {
        return finish("local_tls_mismatch")
    }
    <-done
    if !serverOK {return finish("local_tls_mismatch")}
    result:=finish("local_tls_verified")
    expected:=int64(1)
    if method=="plain" {expected=0}
    if result.AppliedDelta!=expected || result.SkippedDelta!=0 {
        result.Outcome="local_tls_mismatch"
    }
    return result
}

// Capture only the six-byte record/handshake prefix of a local fixture.
// All bytes are delivered unchanged; no socket or certificate policy is
// changed. This is not a complete ServerHello parser or trust decision.
type localTLSReadPrefix struct {
    net.Conn
    prefix [6]byte
    used int
}

func (c *localTLSReadPrefix) Read(b []byte) (int,error) {
    n,err:=c.Conn.Read(b)
    if n>0 && c.used<len(c.prefix) {
        c.used+=copy(c.prefix[c.used:],b[:n])
    }
    return n,err
}

func (c *localTLSReadPrefix) verified() bool {
    return c.used==len(c.prefix) && zapret2.VerifyLocalServerHelloPrefix(c.prefix[:])
}
