//go:build linux

package bridge

import (
    "context"
    "net"
    "errors"
    "io"
    "strings"
    "testing"
    "time"
)

func TestZapret2AllManualModesAndPrivateProbeTags(t *testing.T) {
    names := []string{"plain", "split-1", "split", "tlsrec-split",
        "fake-3", "fake-5", "disorder", "auto", "split-2", "fake-2", "fake-4", "fake-8"}
    if len(zapret2TestStrategies) != len(names) {
        t.Fatalf("strategy catalog incomplete: %+v", zapret2TestStrategies)
    }
    for _, name := range names {
        tag := zapret2TestStrategies[name]
        if name == "plain" {
            if tag != zapret2PlainTag { t.Fatalf("plain tag: %s", tag) }
            continue
        }
        if tag != "dppass:test-"+name { t.Fatalf("%s: bad test tag %s", name, tag) }
        if _, recognized, err := parseDesyncTag("dppass:exp-"+name); !recognized || err != nil {
            t.Fatalf("underlying mode %s: %v", name, err)
        }
    }
}

func TestZapret2HTTPSAllowlistedDestinations(t *testing.T) {
    wants := map[string]zapret2TestTarget{
        "google_final": {"www.google.com", "/", "html", false},
        "google_search": {"www.google.com", "/search?q=site%3Aexample.com", "html", false},
        "youtube_home": {"www.youtube.com", "/", "html", false},
        "youtube_api_transport": {"youtubei.googleapis.com", "/youtubei/v1/browse", "http_transport", false},
        "youtube_api_ipv4": {"youtubei.googleapis.com", "/youtubei/v1/browse", "http_transport", true},
        "youtube_thumbnail": {"i.ytimg.com", "/vi/jNQXAC9IVRw/hqdefault.jpg", "jpeg", false},
    }
    if len(wants) != len(zapret2TestTargets) { t.Fatal("target list changed") }
    for key, want := range wants {
        if got, ok := zapret2TestTargets[key]; !ok || got != want {
            t.Fatalf("%s: got %+v", key, got)
        }
    }
    for _, bad := range []string{"", "../google_final", "https://evil.test/", "youtube_api", "googlevideo.com"} {
        if got := ProbeZapret2HTTPS("auto", bad, 2*time.Second); got.Outcome != "invalid_target" {
            t.Fatalf("unapproved %q returned %q", bad, got.Outcome)
        }
    }
}

func TestZapret2HTMLAndJpegContentValidation(t *testing.T) {
    html := zapret2TestTargets["youtube_home"]
    jpeg := zapret2TestTargets["youtube_thumbnail"]
    api := zapret2TestTargets["youtube_api_transport"]
    for _, tc := range []struct {
        code int
        mime string
        body []byte
        err error
        target zapret2TestTarget
        want string
    }{
        {200, "text/html; charset=utf-8", []byte("<!DOCTYPE html><html>ok"), nil, html, "ok"},
        {200, "text/html", []byte("try again later"), nil, html, "content_invalid"},
        {200, "text/plain", []byte("<html>oops"), nil, html, "content_type_mismatch"},
        {302, "text/html", nil, io.EOF, html, "redirect"},
        {403, "text/html", []byte("denied"), nil, html, "http_status"},
        {200, "text/html", []byte("<html>truncated"), io.ErrUnexpectedEOF, html, "ok"},
        {200, "text/html", []byte("<html>broken"), errors.New("reset"), html, "body_failed"},
        {200, "text/html", nil, io.EOF, html, "empty_body"},
        {400, "application/json", []byte("{}"), io.ErrUnexpectedEOF, api, "http_reachable"},
        {403, "text/plain", []byte("auth required"), io.ErrUnexpectedEOF, api, "http_reachable"},
        {200, "text/html", []byte("<html>"), nil, api, "http_reachable"},
        {301, "text/html", nil, io.EOF, api, "redirect"},
        {500, "application/json", nil, nil, api, "http_status"},
        {200, "image/jpeg", append([]byte{0xff,0xd8,0xff}, make([]byte,256)...), nil, jpeg, "ok"},
        {200, "image/jpeg", []byte("not a jpeg"), nil, jpeg, "content_invalid"},
        {200, "text/html", append([]byte{0xff,0xd8,0xff}, make([]byte,256)...), nil, jpeg, "content_type_mismatch"},
    } {
        if got := classifyProbeHTTP(tc.code, tc.mime, tc.body, tc.err, tc.target); got != tc.want {
            t.Fatalf("http=%d kind=%s: got=%s want=%s", tc.code, tc.target.contentKind, got, tc.want)
        }
    }
}

func TestZapret2ProbeRejectsArbitraryStrategiesAndTimeout(t *testing.T) {
    for _, strategy := range []string{"https://evil.example", "fake-9", "../split", " plain"} {
        if result := ProbeZapret2HTTPS(strategy, "youtube_home", 2*time.Second); result.Outcome != "invalid_strategy" {
            t.Fatalf("accepted %q", strategy)
        }
    }
    if result := ProbeZapret2HTTPS("auto", "google_final", time.Millisecond); result.Outcome != "invalid_timeout" {
        t.Fatalf("accepted invalid timeout: %+v", result)
    }
}

func TestZapret2HTTPSWireDoesNotLeakBodiesOrDestinations(t *testing.T) {
    r := Zapret2HTTPSResult{Outcome:"content_invalid", HTTPStatus:200,
        BodyBytes:15, Elapsed:1500*time.Millisecond, AppliedDelta:2, SkippedDelta:1}
    got := string(r.Wire())
    if got != "v1\tcontent_invalid\t200\t15\t1500\t2\t1" {
        t.Fatalf("wrong probe wire: %q", got)
    }
    if strings.Contains(got, "youtube.com") || strings.Contains(got, "http") {
        t.Fatal("serialized response leaked URL")
    }
}

func TestZapret2TLSPhaseTimeoutDoesNotHideAsGenericTimeout(t *testing.T) {
    // A protected TCP socket has opened, but the TLS peer never sends
    // ServerHello. Report that specific phase, not dial/HTTP timeout.
    client, server := net.Pipe()
    defer client.Close()
    defer server.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
    defer cancel()
    got := probeHTTPSWithConn(ctx, client, zapret2TestTargets["youtube_api_transport"])
    if got.Outcome != "timeout_tls" { t.Fatalf("timeout stage got %s",got.Outcome) }
}

func TestZapret2IPv4ProbeIsTheSameHostAndHTTPRoute(t *testing.T) {
    regular:=zapret2TestTargets["youtube_api_transport"]
    ipv4:=zapret2TestTargets["youtube_api_ipv4"]
    if regular.ipv4Only || !ipv4.ipv4Only || regular.host!=ipv4.host ||
        regular.path!=ipv4.path || regular.contentKind!=ipv4.contentKind {
        t.Fatal("IPv4 control must differ ONLY by its DNS address family")
    }
    if zapret2TestTargets["google_search"].path!="/search?q=site%3Aexample.com" {
        t.Fatal("Google search test path is not a fixed, nonpersonal query")
    }
}

func TestFixedHTTPSDiagnosticFinalizationPreservesEvidenceWithoutPublishing(t *testing.T) {
    for _,outcome:=range []string{"ok","http_reachable","timeout_tls","engine_off"} {
        input:=Zapret2HTTPSResult{Outcome:outcome,HTTPStatus:200,BodyBytes:256,
            DnsFingerprint:"abcdef12",DnsAnswers:2,Protocol:"h1",TLSStage:"tls_verified",ALPN:"http/1.1"}
        _,counters:=newDiagnosticRequestContext(context.Background())
        for i:=0;i<3;i++ {counters.record(true)}
        got:=finalizeHTTPSDiagnostic(input,500*time.Millisecond,counters)
        want:=input
        want.Elapsed=500*time.Millisecond
        want.AppliedDelta=3
        want.SkippedDelta=0
        if got!=want {t.Fatalf("diagnostic %q changed evidence: %+v",outcome,got)}
    }
}
