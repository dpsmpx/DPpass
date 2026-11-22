//go:build linux

package bridge

// Adaptive per-destination strategy selection for protected Xray TCP flows.
// Only successful *payload* delivery earns a preference. An outbound dial or
// TLS ServerHello by itself is not evidence of working video delivery.
// Selected domains are kept in memory; no visited URL or plaintext is logged.
import (
    "errors"
    "strings"
    "sync"
    "unicode"
)

var adaptiveCandidates = [...]string{"split-1", "split", "fake-3", "fake-5", "disorder"}
// 128 KiB of actual downstream traffic is stronger evidence than the
// small JSON/HTML metadata which can load even while media/CDN stalls.
const adaptivePayloadThreshold = 128 * 1024
const adaptiveMaxHosts = 1024
const adaptiveMaxTargets = 512

// Published atomically from a first Write and observed by concurrent Close.
type adaptivePick struct {
    host string
    strategy string
}

type adaptiveEntry struct {
    index int
    preferred string
    weakFailures int
}

type adaptiveSelector struct {
    mu sync.Mutex
    entries map[string]*adaptiveEntry
    selected map[string]struct{}
}

var zapret2Auto = &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}

func canonicalAdaptiveHost(host string) string {
    host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
    // The trailing colon in an HTTP/1 Host header is port separation, not
    // part of an IPv6 address. Do not query DNS to validate or select.
    if i := strings.LastIndexByte(host, ':'); i > 0 && !strings.Contains(host[:i], ":") {
        validPort := len(host[i+1:]) > 0
        for _, c := range host[i+1:] { if c < '0' || c > '9' { validPort = false; break } }
        if validPort { host = host[:i] }
    }
    if len(host) == 0 || len(host) > 253 { return "" }
    for _, r := range host {
        if r > unicode.MaxASCII || !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == ':' || r == '[' || r == ']') { return "" }
    }
    return host
}

// A suffix match is allowed only at a DNS-label boundary. User overrides
// for youtube.com therefore include *.youtube.com but never notyoutube.com.
func (a *adaptiveSelector) wants(host string) bool {
    host = canonicalAdaptiveHost(host)
    if host == "" { return false }
    a.mu.Lock()
    defer a.mu.Unlock()
    for suffix := range a.selected {
        if host == suffix || strings.HasSuffix(host, "."+suffix) { return true }
    }
    return false
}

func (a *adaptiveSelector) configureHosts(text string) error {
    if len(text) > 64*1024 { return errors.New("Zapret2 adaptive host selection exceeds 64 KiB") }
    list := make(map[string]struct{})
    for _, line := range strings.Split(text, "\n") {
        line = strings.TrimSpace(line)
        if line == "" { continue }
        host := canonicalAdaptiveHost(line)
        if host == "" || strings.Contains(host, ":") && !strings.Contains(host, "]") {
            return errors.New("invalid Zapret2 adaptive host")
        }
        // Domain label boundaries, not substring matches.
        if !strings.Contains(host, ".") { return errors.New("adaptive host requires DNS name") }
        list[host] = struct{}{}
        if len(list) > adaptiveMaxTargets { return errors.New("too many adaptive hosts") }
    }
    a.mu.Lock()
    a.selected = list
    a.entries = make(map[string]*adaptiveEntry)
    a.mu.Unlock()
    return nil
}

func ConfigureZapret2AdaptiveHosts(text string) error { return zapret2Auto.configureHosts(text) }

// Each selection advances only for new TCP connections. The chosen strategy
// remains fixed for the lifetime of a TLS connection; changing its packet
// manipulation mid-stream would corrupt the TCP protocol.
func (a *adaptiveSelector) choose(host string) string {
    host = canonicalAdaptiveHost(host)
    if host == "" { return adaptiveCandidates[0] }
    a.mu.Lock()
    defer a.mu.Unlock()
    if len(a.entries) >= adaptiveMaxHosts {
        // Bounded memory under churn; never copy visited hostnames to disk.
        a.entries = make(map[string]*adaptiveEntry)
    }
    e := a.entries[host]
    if e == nil { e = &adaptiveEntry{}; a.entries[host] = e }
    if e.preferred != "" { return e.preferred }
    tag := adaptiveCandidates[e.index%len(adaptiveCandidates)]
    e.index++
    return tag
}

func (a *adaptiveSelector) observe(host, strategy string, payloadBytes int64) {
    host = canonicalAdaptiveHost(host)
    if host == "" { return }
    a.mu.Lock()
    defer a.mu.Unlock()
    e := a.entries[host]
    if e == nil { return }
    if payloadBytes >= adaptivePayloadThreshold {
        e.preferred = strategy
        e.weakFailures = 0
    } else if e.preferred == strategy {
        // A single short response can be a legitimate small HTTP request;
        // require two weak endings to leave an otherwise successful mode.
        e.weakFailures++
        if e.weakFailures >= 2 { e.preferred = ""; e.weakFailures = 0 }
    }
}

func ResetZapret2AdaptiveLearning() {
    zapret2Auto.mu.Lock()
    zapret2Auto.entries = make(map[string]*adaptiveEntry)
    zapret2Auto.mu.Unlock()
}
