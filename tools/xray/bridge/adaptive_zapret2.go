//go:build linux

package bridge

// Adaptive per-destination strategy selection for protected Xray TCP flows.
// Only successful *payload* delivery earns a preference. An outbound dial or
// TLS ServerHello by itself is not evidence of working video delivery.
// Selected domains are kept in memory; no visited URL or plaintext is logged.
import (
    "errors"
    "strings"
    "net"
    "sync"
    "time"
    "unicode"
)

// Keep the five established TCP techniques, then lossless TLS-record splitting.
// An unmodified TCP baseline is the final AUTO candidate for unfiltered networks.
var adaptiveCandidates = [...]string{"split-1", "split", "fake-3", "fake-5", "disorder", "tlsrec-split", "pass"}
// HTTP/1 cannot use TLS-record splitting, but can use the plain baseline.
var adaptiveHTTPCandidates = [...]string{"split-1", "split", "fake-3", "fake-5", "disorder", "pass"}
// After the existing fake-3/fake-5 attempts, test ordinary QUIC instead
// of assuming that a random-ciphertext Initial always deceives the DPI.
var adaptiveQuicCandidates = [...]string{"fake-3", "fake-5", "pass"}
// 128 KiB of actual downstream traffic is stronger evidence than the
// small JSON/HTML metadata which can load even while media/CDN stalls.
const adaptivePayloadThreshold = 128 * 1024
// Feed/API responses can be smaller than a media segment. Repeated
// nontrivial payloads are weak evidence, not a successful video probe.
const adaptiveSmallResponseThreshold = 12 * 1024
const adaptiveSmallResponseCount = 3
const adaptiveMaxHosts = 1024
const adaptiveMaxTargets = 512
// A transient no-reply timeout is not proof of DPI. After two independent
// read timeouts with the same method on the same host+protocol, pause that
// method briefly instead of repeatedly blocking new connections.
const adaptiveStallThreshold = 2
const adaptiveStallCooldown = 90 * time.Second

// Published atomically from a first Write and observed by concurrent Close.
type adaptivePick struct {
    host string
    strategy string
    generation uint64
}

type adaptiveEntry struct {
    index int
    preferred string
    // Second independently validated HTTPS profile for this exact hostname.
    // Used only when the preferred profile enters its timeout circuit breaker.
    // Never inferred from QUIC handshakes or shared-IP observations.
    verifiedFallback string
    weakFailures int
    plainReachable bool
    smallResponses map[string]int
    probeSeeded bool // eligible for smaller verified-HTML responses
    usage map[string]int // bounded per-destination cold-start exploration
    stalls map[string]int // per-method consecutive verified ClientHello read timeouts
    cooldown map[string]time.Time // short-lived per-method circuit breaker
}

// Probe evidence is distinct from transport-byte heuristics. It comes from
// certificate-verified HTTPS HTML in the one-button test, for *one exact*
// allowlisted host, and expires at network/session reconfiguration.
type adaptiveProbeSample struct {
    tried int
    verified int
    totalMillis int64
}

type adaptiveProbeEvidence struct {
    lastStrategy string
    plainFailures int
    plainSuccesses int
    candidates map[string]adaptiveProbeSample
    winner string
    winnerMillis int64
}

type adaptiveSelector struct {
    mu sync.Mutex
    entries map[string]*adaptiveEntry
    selected map[string]struct{}
    probe map[string]*adaptiveProbeEvidence
    generation uint64 // invalidates observations from old network sessions
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

// A live key may contain a concrete TCP peer after |. Never persist this
// address in neural sparse keys or reuse host-only probe evidence for it.
func adaptiveHostOnly(key string) string { return strings.SplitN(key, "|", 2)[0] }
func canonicalAdaptiveKey(key string) string {
    parts := strings.SplitN(key, "|", 2)
    host := canonicalAdaptiveHost(parts[0])
    if host == "" || len(parts) == 1 { return host }
    ip := net.ParseIP(parts[1])
    if ip == nil { return "" }
    return host + "|" + ip.String()
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
    a.generation++
    a.entries = make(map[string]*adaptiveEntry)
    a.probe = nil
    a.mu.Unlock()
    return nil
}

func ConfigureZapret2AdaptiveHosts(text string) error { return zapret2Auto.configureHosts(text) }

// Each selection advances only for new TCP connections. The chosen strategy
// remains fixed for the lifetime of a TLS connection; changing its packet
// manipulation mid-stream would corrupt the TCP protocol.
func (a *adaptiveSelector) choose(host string) string {
    choice, _ := a.chooseWithGeneration(host, adaptiveCandidates[:])
    return choice
}
func (a *adaptiveSelector) chooseTracked(host string) (string, uint64) {
    return a.chooseWithGeneration(host, adaptiveCandidates[:])
}

// Plain HTTP/1 Host headers are eligible for legacy TCP tricks, but not
// TLS-record rewriting. A learned TLS-only winner must not disable
// desynchronization for a subsequent HTTP request to the same destination.
func (a *adaptiveSelector) chooseHTTPTracked(host string) (string, uint64) {
    // HTTP and TLS share a destination but not the same usable strategies.
    // Keep their live observations independent; HTTPS probe evidence stays
    // with the original TLS hostname.
    return a.chooseWithGeneration("http:"+host, adaptiveHTTPCandidates[:])
}

// QUIC evidence is separate and keyed by the protected UDP destination IP.
func (a *adaptiveSelector) chooseQUIC(host string) string {
    choice, _ := a.chooseQUICTracked(host)
    return choice
}
func (a *adaptiveSelector) chooseQUICTracked(host string) (string, uint64) {
    return a.chooseWithGeneration("udp:"+host, adaptiveQuicCandidates[:])
}
func (a *adaptiveSelector) chooseFrom(host string, candidates []string) string {
    choice, _ := a.chooseWithGeneration(host, candidates)
    return choice
}

// Previous-network connections may close after a network reset. The captured
// generation prevents their late evidence changing the new network's winner.
func (a *adaptiveSelector) chooseWithGeneration(host string, candidates []string) (string, uint64) {
    return a.choosePolicy(host, candidates, false)
}

// Live traffic starts with the untouched transport. A received reply can
// retain this baseline without pretending that application content worked.
func (a *adaptiveSelector) chooseLive(host string, candidates []string) (string, uint64) {
    return a.choosePolicy(host, candidates, true)
}

func (a *adaptiveSelector) choosePolicy(host string, candidates []string, directFirst bool) (string, uint64) {
    host = canonicalAdaptiveKey(host)
    a.mu.Lock()
    defer a.mu.Unlock()
    if host == "" { if directFirst { return "pass", a.generation }; return candidates[0], a.generation }
    if len(a.entries) >= adaptiveMaxHosts {
        a.entries = make(map[string]*adaptiveEntry)
    }
    e := a.entries[host]
    if e == nil { e = &adaptiveEntry{}; a.entries[host] = e }
    now := time.Now()
    blocked := func(strategy string) bool {
        if e.cooldown == nil { return false }
        until, exists := e.cooldown[strategy]
        if !exists { return false }
        if !now.Before(until) {
            delete(e.cooldown, strategy)
            return false
        }
        return true
    }
    if e.preferred != "" {
        for _, candidate := range candidates {
            if candidate == e.preferred && !blocked(e.preferred) {
                return e.preferred, a.generation
            }
        }
        if blocked(e.preferred) {
            // The alternate was verified 3/3 on the same pinned addresses
            // during the same explicit scan. It remains scoped to this
            // host and generation; no retry within an existing TCP flow.
            fallback := e.verifiedFallback
            e.preferred = ""
            e.plainReachable = false
            e.probeSeeded = false
            e.verifiedFallback = ""
            if fallback != "" && !blocked(fallback) {
                for _, candidate := range candidates {
                    if candidate == fallback {
                        e.preferred = fallback
                        e.probeSeeded = true
                        return fallback, a.generation
                    }
                }
            }
        }
    }
    if directFirst && e.index == 0 && !blocked("pass") {
        e.index++
        if e.usage == nil { e.usage = make(map[string]int) }
        e.usage["pass"]++
        return "pass", a.generation
    }
    // Preserve established candidate ordering and the plain baseline
    // unless an independent timeout-based circuit breaker is active.
    index := e.index
    if directFirst && index > 0 { index-- }
    tag := candidates[index%len(candidates)]
    for offset := 0; offset < len(candidates); offset++ {
        choice := candidates[(index+offset)%len(candidates)]
        if !blocked(choice) {
            tag = choice
            break
        }
    }
    // The optional locally generated MLP influences cold-start ordering only;
    // every fifth connection still explores the deterministic rotation.
    // A local neural prior must not suppress the plain TCP baseline.
    // Always try "pass" when its deterministic turn arrives, even with MLP.
    if tag != "pass" && e.index%5 != 4 {
        if ranked, ok := zapret2Neural.rank(adaptiveHostOnly(host), candidates, e.usage); ok && !blocked(ranked) {
            tag = ranked
        }
    }
    e.index++
    if e.usage == nil { e.usage = make(map[string]int) }
    if e.usage[tag] < 100 { e.usage[tag]++ }
    return tag, a.generation
}

// First real TCP reply is reachability only. Never train the MLP here.
func (a *adaptiveSelector) retainPlainReply(host string, generation uint64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.generation != generation { return }
    e := a.entries[canonicalAdaptiveKey(host)]
    if e == nil { return }
    e.preferred = "pass"
    e.plainReachable = true
    e.probeSeeded = false
    e.weakFailures = 0
    delete(e.stalls, "pass")
    delete(e.cooldown, "pass")
}

func (a *adaptiveSelector) observe(host, strategy string, payloadBytes int64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    a.observeLocked(host, strategy, payloadBytes)
}
func (a *adaptiveSelector) observeTracked(host, strategy string, payloadBytes int64, generation uint64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.generation != generation { return }
    a.observeLocked(host, strategy, payloadBytes)
}

// A first-reply timeout is stronger evidence than an ordinary Close with
// zero bytes: the application may deliberately cancel an unopened request.
// Keep only one event per connection (desyncConn.stageReadTimedOut).
func (a *adaptiveSelector) observeStallTracked(host, strategy string, generation uint64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.generation != generation { return }
    host = canonicalAdaptiveKey(host)
    e := a.entries[host]
    if e == nil { return }
    known := false
    for _, candidate := range adaptiveCandidates {
        if candidate == strategy { known = true; break }
    }
    if !known { return }
    if e.stalls == nil { e.stalls = make(map[string]int) }
    e.stalls[strategy]++
    if e.stalls[strategy] >= adaptiveStallThreshold {
        if e.cooldown == nil { e.cooldown = make(map[string]time.Time) }
        e.cooldown[strategy] = time.Now().Add(adaptiveStallCooldown)
        e.stalls[strategy] = 0
        if e.preferred == strategy {
            // Promote only a second profile that independently passed 3/3
            // HTTPS on every same-run pinned IP. Never use it for QUIC.
            backup := e.verifiedFallback
            e.verifiedFallback = ""
            e.preferred = ""
            e.plainReachable = false
            e.probeSeeded = false
            e.weakFailures = 0
            e.smallResponses = nil
            if backup != "" {
                until := e.cooldown[backup]
                if !time.Now().Before(until) {
                    e.preferred = backup
                    e.probeSeeded = true
                }
            }
        }
    }
    a.observeLocked(host, strategy, 0)
}

func (a *adaptiveSelector) observeLocked(host, strategy string, payloadBytes int64) {
    host = canonicalAdaptiveKey(host)
    e := a.entries[host]
    if e == nil { return }
    // Meaningful downstream data clears previous timeout suspicions for
    // this exact host, transport and technique. Mere TCP dial success,
    // HTTP headers or a zero-byte Close never clears the circuit breaker.
    if payloadBytes >= adaptiveSmallResponseThreshold {
        if e.stalls != nil { delete(e.stalls, strategy) }
        if e.cooldown != nil { delete(e.cooldown, strategy) }
    }
    // The same observations drive the old conservative per-host pinning
    // AND, if explicitly installed, the optional global neural prior.
    // Do not train on simulated selectors used by unit tests.
    if a == zapret2Auto { zapret2Neural.learn(adaptiveHostOnly(host), strategy, payloadBytes) }
    if e.plainReachable && e.preferred == "pass" && strategy != "pass" { return }
    if payloadBytes >= adaptivePayloadThreshold {
        // A different candidate with a full-sized downstream flow may
        // supersede the HTML hint. The SAME verified candidate should not
        // lose its small-success threshold after one large response.
        if e.preferred != strategy { e.probeSeeded = false }
        e.preferred = strategy
        e.weakFailures = 0
        e.smallResponses = nil
    } else if e.preferred == strategy {
        if strategy == "pass" && payloadBytes > 0 { e.weakFailures = 0; return }
        // A verified HTML probe earns a *temporary* preference. Its
        // successful 8 KiB page sample must not be misclassified as a
        // failure merely because the media-oriented default is 12 KiB.
        threshold := int64(adaptiveSmallResponseThreshold)
        if e.probeSeeded { threshold = 4 * 1024 }
        if payloadBytes >= threshold {
            e.weakFailures = 0
        } else {
            e.weakFailures++
            if e.weakFailures >= 2 {
                e.preferred = ""
            e.plainReachable = false
                e.probeSeeded = false
                e.weakFailures = 0
                e.smallResponses = nil
            }
        }
    } else if e.preferred == "" && payloadBytes >= adaptiveSmallResponseThreshold {
        // Several small feed/API responses can demonstrate progress without
        // a 128-KiB media segment. Never pin from only one handshake.
        if e.smallResponses == nil { e.smallResponses = make(map[string]int) }
        e.smallResponses[strategy]++
        if e.smallResponses[strategy] >= adaptiveSmallResponseCount {
            e.preferred = strategy
            e.weakFailures = 0
            e.smallResponses = nil
        }
    }
}

// Current generation identifies observations from a single network session.
func (a *adaptiveSelector) generationSnapshot() uint64 {
    a.mu.Lock()
    defer a.mu.Unlock()
    return a.generation
}

// Two independent exact-host kinds of diagnostic evidence:
// - www.youtube.com: validated HTTP 200 HTML content (outcome=ok)
// - youtubei.googleapis.com: TLS-verified HTTP 2xx/4xx response
//   (outcome=http_reachable), which proves transport ONLY, not a feed.
// Neither permits promoting strategies for unrelated Googlevideo/CDN/Google
// domains. Do not train from redirects, one success, or TLS bytes alone.
func (a *adaptiveSelector) observeHTMLProbe(host, strategy, outcome string, elapsedMillis int64, generation uint64) {
    a.observeVerifiedProbe(host, "www.youtube.com", "ok",
        strategy, outcome, elapsedMillis, generation)
}

func (a *adaptiveSelector) observeAPITransportProbe(host, strategy, outcome string, elapsedMillis int64, generation uint64) {
    a.observeVerifiedProbe(host, "youtubei.googleapis.com", "http_reachable",
        strategy, outcome, elapsedMillis, generation)
}

func (a *adaptiveSelector) observeVerifiedProbe(host, requiredHost, validOutcome,
    strategy, outcome string, elapsedMillis int64, generation uint64) {
    if host != requiredHost || strategy == "auto" || elapsedMillis < 0 { return }
    if strategy != "plain" {
        recognized := false
        for _, candidate := range adaptiveCandidates {
            if strategy == candidate { recognized = true; break }
        }
        if !recognized { return }
    }

    a.mu.Lock()
    defer a.mu.Unlock()
    if a.generation != generation { return }
    if a.probe == nil { a.probe = make(map[string]*adaptiveProbeEvidence) }
    evidence := a.probe[host]
    // Start a new trial on the first plain attempt after another strategy.
    // A test runs one baseline pair, then candidate pairs, serially.
    if evidence == nil || strategy == "plain" && evidence.lastStrategy != "plain" ||
        strategy == "plain" && evidence.plainFailures+evidence.plainSuccesses >= 2 {
        evidence = &adaptiveProbeEvidence{candidates: make(map[string]adaptiveProbeSample)}
        a.probe[host] = evidence
    }
    evidence.lastStrategy = strategy
    if strategy == "plain" {
        if outcome == validOutcome { evidence.plainSuccesses++ }
        // A timeout in any transport stage is still a failed baseline.
        // Keep specific outcome codes for diagnostics, not as proof of DPI.
        if outcome == "timeout" || strings.HasPrefix(outcome, "timeout_") ||
            outcome == "dial_failed" || outcome == "tls_failed" {
            evidence.plainFailures++
        }
        return
    }
    sample := evidence.candidates[strategy]
    sample.tried++
    if outcome == validOutcome {
        sample.verified++
        sample.totalMillis += elapsedMillis
    }
    evidence.candidates[strategy] = sample

    if evidence.plainFailures != 2 || evidence.plainSuccesses != 0 ||
        sample.tried != 2 || sample.verified != 2 {
        return
    }
    // Prefer a confirmed same-host transport/content winner with lower
    // total latency; do not mistake a redirect or a single success for proof.
    if evidence.winner != "" && sample.totalMillis >= evidence.winnerMillis { return }
    evidence.winner, evidence.winnerMillis = strategy, sample.totalMillis
    e := a.entries[host]
    if e == nil {
        if len(a.entries) >= adaptiveMaxHosts {
            a.entries = make(map[string]*adaptiveEntry)
        }
        e = &adaptiveEntry{}
        a.entries[host] = e
    }
    e.preferred = strategy
    e.probeSeeded = true
    e.weakFailures = 0
    e.smallResponses = nil
    // On two weak live connections, fall back to a *different* candidate.
    // If the other successful method was observed, try it first.
    backup := "fake-5"
    if strategy == "fake-5" { backup = "tlsrec-split" }
    for i, candidate := range adaptiveCandidates {
        if candidate == backup { e.index = i; break }
    }
}

// Reset all temporary knowledge when the network changes. Never persist
// the target's browsing history or the probe winner to preferences.
func ResetZapret2AdaptiveLearning() {
    zapret2Auto.mu.Lock()
    zapret2Auto.entries = make(map[string]*adaptiveEntry)
    zapret2Auto.probe = nil
    zapret2Auto.generation++
    zapret2Auto.mu.Unlock()
}
