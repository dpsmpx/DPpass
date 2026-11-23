//go:build linux

package bridge

// One-button, protected Xray HTTPS probes. All targets and paths are hardcoded
// and allowlisted: no arbitrary URL, redirects, credentials, or payload logs.
import (
    "bufio"
    "bytes"
    "context"
    "crypto/tls"
    "crypto/x509"
    "errors"
    "fmt"
    "io"
    "net"
    "net/http"
    "strings"
    "time"

    xnet "github.com/xtls/xray-core/common/net"
    "github.com/xtls/xray-core/common/session"
    "github.com/xtls/xray-core/core"
)

const zapret2TestBodyLimit = 8192
const zapret2PlainTag = "dppass:test-plain"

// Separate entry tags from protected exp dialers; every candidate uses the
// same DNS resolution policy and the live socket-protection hook.
var zapret2TestStrategies = map[string]string{
    "plain": zapret2PlainTag,
    "split-1": "dppass:test-split-1",
    "split": "dppass:test-split",
    "tlsrec-split": "dppass:test-tlsrec-split",
    "fake-3": "dppass:test-fake-3",
    "fake-5": "dppass:test-fake-5",
    "disorder": "dppass:test-disorder",
    "auto": "dppass:test-auto",
}

type zapret2TestTarget struct {
    host string
    path string
    contentKind string
    ipv4Only bool
}

// google_final is the known google.com 301 destination, requested directly.
// YouTube HTML and one stable public thumbnail test different service hosts.
// A thumbnail on i.ytimg.com is not a googlevideo media-streaming proof.
var zapret2TestTargets = map[string]zapret2TestTarget{
    "google_final": {"www.google.com", "/", "html", false},
    // A fixed non-personal query exercises /search rather than only /.
    // HTML from this endpoint does NOT prove useful search results.
    "google_search": {"www.google.com", "/search?q=site%3Aexample.com", "html", false},
    "youtube_home": {"www.youtube.com", "/", "html", false},
    // A credentials-free request cannot validate the real mobile API.
    // HTTP 4xx still proves TLS+HTTP reachability, not app feed content.
    "youtube_api_transport": {"youtubei.googleapis.com", "/youtubei/v1/browse", "http_transport", false},
    // Control arm: the SAME host/path/strategy, with ForceIPv4 exclusively
    // on the PRIVATE test freedom outbound, not production VPN traffic.
    "youtube_api_ipv4": {"youtubei.googleapis.com", "/youtubei/v1/browse", "http_transport", true},
    "youtube_thumbnail": {"i.ytimg.com", "/vi/jNQXAC9IVRw/hqdefault.jpg", "jpeg", false},
}

// All reported fields are numbers and fixed outcome codes; no page bodies,
// request paths, hostnames or addresses are serialized over JNI.
type Zapret2HTTPSResult struct {
    Outcome string
    HTTPStatus int
    BodyBytes int64
    Elapsed time.Duration
    AppliedDelta int64
    SkippedDelta int64
    // Only nonempty for fixed-DoH experimental controls. No raw IPs.
    DnsFingerprint string
    DnsAnswers int
}

func (r Zapret2HTTPSResult) Wire() []byte {
    if r.DnsFingerprint!="" {
        return []byte(fmt.Sprintf("v2\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%d",
            r.Outcome,r.HTTPStatus,r.BodyBytes,r.Elapsed.Milliseconds(),
            r.AppliedDelta,r.SkippedDelta,r.DnsFingerprint,r.DnsAnswers))
    }
    return []byte(fmt.Sprintf("v1\t%s\t%d\t%d\t%d\t%d\t%d",
        r.Outcome, r.HTTPStatus, r.BodyBytes, r.Elapsed.Milliseconds(),
        r.AppliedDelta, r.SkippedDelta))
}

func classifyProbeHTTP(code int, contentType string, body []byte, readErr error, target zapret2TestTarget) string {
    if code >= 300 && code < 400 { return "redirect" }
    // This is ONLY a transport probe: unauthenticated GET on an API that
    // normally needs POST/keys. 4xx is not working feed content.
    if target.contentKind == "http_transport" {
        if code >= 200 && code < 500 { return "http_reachable" }
        return "http_status"
    }
    if code < 200 || code >= 300 { return "http_status" }
    if readErr != nil && !errors.Is(readErr, io.EOF) && !errors.Is(readErr, io.ErrUnexpectedEOF) {
        return "body_failed"
    }
    if len(body) == 0 { return "empty_body" }
    ct := strings.ToLower(contentType)
    switch target.contentKind {
    case "html":
        if !strings.Contains(ct, "text/html") { return "content_type_mismatch" }
        prefix := bytes.ToLower(body[:min(2048,len(body))])
        if !bytes.Contains(prefix, []byte("<html")) && !bytes.Contains(prefix, []byte("<!doctype html")) {
            return "content_invalid"
        }
    case "jpeg":
        if !strings.Contains(ct, "image/jpeg") { return "content_type_mismatch" }
        if len(body) < 128 || !bytes.HasPrefix(body, []byte{0xff, 0xd8, 0xff}) { return "content_invalid" }
    default:
        return "invalid_target"
    }
    return "ok"
}

func probeHTTPSWithConn(ctx context.Context, c net.Conn, target zapret2TestTarget) Zapret2HTTPSResult {
    result := Zapret2HTTPSResult{Outcome: "tls_failed"}
    tc := tls.Client(c, &tls.Config{
        ServerName: target.host,
        RootCAs: probeRoots, // nil uses Android/platform roots
        NextProtos: []string{"http/1.1"},
        MinVersion: tls.VersionTLS12,
    })
    defer tc.Close()
    if err := tc.HandshakeContext(ctx); err != nil {
        var unknownAuthority x509.UnknownAuthorityError
        switch {
        case errors.As(err, &unknownAuthority): result.Outcome = "tls_ca_failed"
        case ctx.Err() != nil: result.Outcome = "timeout_tls"
        }
        return result
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodGet,
        "https://"+target.host+target.path, nil)
    if err != nil { result.Outcome = "request_failed"; return result }
    req.Header.Set("Accept", "text/html,image/jpeg")
    req.Header.Set("Accept-Encoding", "identity")
    req.Close = true
    if err = req.Write(tc); err != nil {
        result.Outcome = "request_failed"
        if ctx.Err() != nil { result.Outcome = "timeout_write" }
        return result
    }
    resp, err := http.ReadResponse(bufio.NewReader(tc), req)
    if err != nil {
        result.Outcome = "http_failed"
        if ctx.Err() != nil { result.Outcome = "timeout_headers" }
        return result
    }
    defer resp.Body.Close()
    result.HTTPStatus = resp.StatusCode

    // A small fixed read proves the expected HTML/JPEG content exists,
    // but never stores it beyond this stack or returns it to Kotlin.
    bounded := make([]byte, zapret2TestBodyLimit)
    n, readErr := io.ReadFull(resp.Body, bounded)
    result.BodyBytes = int64(n)
    result.Outcome = classifyProbeHTTP(resp.StatusCode, resp.Header.Get("Content-Type"),
        bounded[:n], readErr, target)
    if ctx.Err() != nil && result.Outcome == "body_failed" {
        result.Outcome = "timeout_body"
    }
    return result
}

// ProbeZapret2HTTPS performs exactly one network request via an allowlisted
// private outbound, without changing the active VPN routing or strategy.
// The UI calls this serially on a background thread, per-attempt timeout.
func ProbeZapret2HTTPS(strategy, targetID string, timeout time.Duration) Zapret2HTTPSResult {
    started := time.Now()
    out := Zapret2HTTPSResult{Outcome:"invalid_strategy"}
    tag, valid := zapret2TestStrategies[strategy]
    if !valid { return out }
    target, valid := zapret2TestTargets[targetID]
    dohProvider := ""
    if !valid && strings.HasPrefix(targetID,"youtube_api_dns_") {
        p:=strings.TrimPrefix(targetID,"youtube_api_dns_")
        if validateFixedDoHProvider(p) {
            dohProvider=p
            target=zapret2TestTargets["youtube_api_ipv4"]
            valid=true
        }
    }
    if !valid { out.Outcome = "invalid_target"; return out }
    if target.ipv4Only { tag += "-ipv4" }
    if timeout < time.Second || timeout > 15*time.Second {
        out.Outcome = "invalid_timeout"
        return out
    }
    beforeApplied, beforeSkipped := DesyncStats()
    generation := zapret2Auto.generationSnapshot()
    finish := func(r Zapret2HTTPSResult) Zapret2HTTPSResult {
        nowApplied, nowSkipped := DesyncStats()
        r.AppliedDelta = max(0, nowApplied-beforeApplied)
        r.SkippedDelta = max(0, nowSkipped-beforeSkipped)
        r.Elapsed = time.Since(started)
        // Only the hardcoded www.youtube.com HTML target may teach AUTO.
        // Verified page bytes, not TCP/TLS or a 301, are required.
        // The selector rejects late evidence from a previous VPN session.
        switch targetID {
        case "youtube_home":
            zapret2Auto.observeHTMLProbe(target.host, strategy, r.Outcome,
                r.Elapsed.Milliseconds(), generation)
        case "youtube_api_transport":
            // A 4xx with valid TLS proves HTTP transport only. Learn a
            // different exact-host preference; never call it API success.
            zapret2Auto.observeAPITransportProbe(target.host, strategy, r.Outcome,
                r.Elapsed.Milliseconds(), generation)
        }
        return r
    }
    mu.Lock()
    inst := current
    mu.Unlock()
    if inst == nil {
        out.Outcome = "engine_off"
        return finish(out)
    }
    ctx, cancel := context.WithTimeout(context.Background(), timeout)
    defer cancel()
    if dohProvider!="" {
        return finish(probeWithFixedDoH(ctx,inst,strategy,dohProvider,target))
    }
    dest := xnet.Destination{Network:xnet.Network_TCP,
        Address:xnet.ParseAddress(target.host), Port:443}
    forced := session.SetForcedOutboundTagToContext(ctx, tag)
    raw, err := core.Dial(forced, inst, dest)
    if err != nil {
        out.Outcome = "dial_failed"
        if ctx.Err() != nil { out.Outcome = "timeout_dial" }
        return finish(out)
    }
    defer raw.Close()
    done := make(chan struct{})
    defer close(done)
    go func() {
        select {
        case <-ctx.Done(): _ = raw.Close()
        case <-done:
        }
    }()
    result := probeHTTPSWithConn(ctx, raw, target)
    // Preserve the phase where the timeout occurred. A generic timeout
    // used to hide failures after ClientHello or after the HTTP request.
    return finish(result)
}
