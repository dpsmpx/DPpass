//go:build linux

package bridge

// A user-triggered, serverless HTTPS A/B probe. This is not a browser and
// cannot inspect YouTube's encrypted application traffic. It sends only a
// bounded GET https://google.com/ through a private Xray test outbound, and
// leaves the active VPN routing and user-selected strategy untouched.
import (
    "bufio"
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

const Zapret2TestHost = "google.com"
const zapret2TestBodyLimit = 8192
const zapret2PlainTag = "dppass:test-plain"

// Strategies must match engine.Zapret2ProbeCatalog. Never accept an
// arbitrary outbound tag or URL from Java or user input.
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

// Zapret2HTTPSResult carries only a stage/status and aggregate measurements.
// Applied/skipped deltas are process-wide and may include unrelated apps;
// they MUST NOT be represented as proof that this probe's trick was applied.
type Zapret2HTTPSResult struct {
    Outcome string
    HTTPStatus int
    BodyBytes int64
    Elapsed time.Duration
    AppliedDelta int64
    SkippedDelta int64
}

func (r Zapret2HTTPSResult) Wire() []byte {
    return []byte(fmt.Sprintf("v1\t%s\t%d\t%d\t%d\t%d\t%d",
        r.Outcome, r.HTTPStatus, r.BodyBytes, r.Elapsed.Milliseconds(),
        r.AppliedDelta, r.SkippedDelta))
}

func classifyGoogleHTTP(code int, bodyBytes int64, readErr error) string {
    if code >= 300 && code < 400 { return "redirect" } // TLS + HTTP response; no second domain
    if code < 200 || code >= 300 { return "http_status" }
    if readErr != nil { return "body_failed" }
    if bodyBytes == 0 { return "empty_body" }
    return "ok"
}

func probeGoogleHTTPSWithConn(ctx context.Context, c net.Conn) Zapret2HTTPSResult {
    result := Zapret2HTTPSResult{Outcome: "tls_failed"}
    tc := tls.Client(c, &tls.Config{
        ServerName: Zapret2TestHost,
        RootCAs: probeRoots, // nil -> platform roots; never disable verification
        NextProtos: []string{"http/1.1"},
        MinVersion: tls.VersionTLS12,
    })
    defer tc.Close()
    if err := tc.HandshakeContext(ctx); err != nil {
        var unknownAuthority x509.UnknownAuthorityError
        if errors.As(err, &unknownAuthority) { result.Outcome = "tls_ca_failed" }
        return result
    }
    request, err := http.NewRequestWithContext(ctx, http.MethodGet,
        "https://"+Zapret2TestHost+"/", nil)
    if err != nil { result.Outcome = "request_failed"; return result }
    request.Header.Set("Accept", "text/html")
    request.Header.Set("Accept-Encoding", "identity")
    request.Close = true
    if err = request.Write(tc); err != nil {
        result.Outcome = "request_failed"
        return result
    }
    resp, err := http.ReadResponse(bufio.NewReader(tc), request)
    if err != nil {
        result.Outcome = "http_failed"
        return result
    }
    defer resp.Body.Close()
    result.HTTPStatus = resp.StatusCode
    // Stop after 8 KiB: enough to prove Google returned content, never
    // collect or log the body itself. Google may return HTTP 301; this is a
    // valid HTTP response and not evidence that www.google.com also works.
    bytesRead, readErr := io.Copy(io.Discard,
        io.LimitReader(resp.Body, zapret2TestBodyLimit))
    result.BodyBytes = bytesRead
    result.Outcome = classifyGoogleHTTP(resp.StatusCode, bytesRead, readErr)
    return result
}

// ProbeZapret2HTTPS sends exactly one test request. It does not restart
// Xray or the VPN. The caller should invoke it on a worker thread and
// perform the 8 strategies serially; every attempt has a hard timeout.
func ProbeZapret2HTTPS(strategy string, timeout time.Duration) Zapret2HTTPSResult {
    started := time.Now()
    out := Zapret2HTTPSResult{Outcome:"invalid_strategy"}
    tag, valid := zapret2TestStrategies[strings.TrimSpace(strategy)]
    if !valid || strategy != strings.TrimSpace(strategy) { return out }
    if timeout < time.Second || timeout > 15*time.Second {
        out.Outcome = "invalid_timeout"
        return out
    }
    beforeApplied, beforeSkipped := DesyncStats()
    finish := func(r Zapret2HTTPSResult) Zapret2HTTPSResult {
        nowApplied, nowSkipped := DesyncStats()
        r.AppliedDelta = max(0, nowApplied-beforeApplied)
        r.SkippedDelta = max(0, nowSkipped-beforeSkipped)
        r.Elapsed = time.Since(started)
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
    address := xnet.ParseAddress(Zapret2TestHost)
    dest := xnet.Destination{Network:xnet.Network_TCP,Address:address,Port:443}
    forced := session.SetForcedOutboundTagToContext(ctx, tag)
    raw, err := core.Dial(forced, inst, dest)
    if err != nil {
        out.Outcome = "dial_failed"
        if ctx.Err() != nil { out.Outcome = "timeout" }
        return finish(out)
    }
    defer raw.Close()
    stopped := make(chan struct{})
    defer close(stopped)
    go func() {
        select {
        case <-ctx.Done(): _ = raw.Close()
        case <-stopped:
        }
    }()
    r := probeGoogleHTTPSWithConn(ctx, raw)
    if ctx.Err() != nil && r.Outcome != "ok" && r.Outcome != "redirect" {
        r.Outcome = "timeout"
    }
    return finish(r)
}
