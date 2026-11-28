//go:build linux

package bridge

// Adaptive per-destination strategy selection for protected Xray TCP flows.
// Only successful *payload* delivery earns a preference. An outbound dial or
// TLS ServerHello by itself is not evidence of working video delivery.
// Selected domains are kept in memory; no visited URL or plaintext is logged.
import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
    "errors"
    "strings"
    "net"
    "maps"
    "sync"
    "time"
    "strconv"
)

// Explicitly register the existing protected socket executor. The catalog
// is not a promise of support by any executor; future catalog entries do
// not automatically become candidates in this path.
var socketCapabilities = newSocketCapabilities()

func newSocketCapabilities() localdpi.Capabilities {
    entries := []localdpi.Support{}
    for _, id := range []string{"split-1","split","fake-3","fake-5","disorder","tlsrec-split","pass"} {
        entries = append(entries, localdpi.Support{Transport:localdpi.TLS,MethodID:id})
    }
    // The catalog and the protected socket planner both restrict
    // split-1 and tlsrec-split to TLS.
    for _, id := range []string{"split","fake-3","fake-5","disorder","pass"} {
        entries = append(entries, localdpi.Support{Transport:localdpi.HTTP,MethodID:id})
    }
    for _, id := range []string{"fake-3","fake-5","pass"} {
        entries = append(entries, localdpi.Support{Transport:localdpi.QUIC,MethodID:id})
    }
    caps, err := localdpi.NewCapabilities(localdpi.VPNSocket,false,entries)
    if err != nil { panic("invalid compiled socket capabilities: "+err.Error()) }
    return caps
}
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
    owner *adaptiveSelector
    host string
    flow localdpi.FlowIdentity
    entryID uint64 // identity of the admitted cache entry, not its recency
}

// The immutable flow identity is captured when the transport selects a
// method, not reconstructed later from an observation. The existing
// selector still checks network generation under its lock.
func (a *adaptiveSelector) newSocketPick(host, method string, generation uint64, transport localdpi.Transport) *adaptivePick {
    return &adaptivePick{
        owner: a,
        host: host,
        flow: localdpi.FlowIdentity{
            Executor: a.capabilities.Kind(), Generation: generation, Transport: transport, MethodID: method,
        },
    }
}

func socketPickAdmissible(pick *adaptivePick) bool {
    if pick == nil || pick.owner == nil || pick.host == "" {
        return false
    }
    if pick.flow.Executor != localdpi.VPNSocket && pick.flow.Executor != localdpi.RootSocket {
        return false
    }
    return nnHostTransport(pick.host) == pick.flow.Transport &&
        pick.flow.Matches(pick.owner.capabilities, pick.flow.Generation)
}

func socketEvidenceAdmissible(pick *adaptivePick, evidence localdpi.Evidence) bool {
    return socketPickAdmissible(pick) && evidence.ValidSocketObservation()
}

type adaptiveEntry struct {
    entryID uint64 // fixed for the lifetime of this cache entry
    lastUsed uint64 // selector-local recency, not persisted
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

// clearPreference retires only preference-local state. Per-method health
// and exploration history belong to the destination, not to its winner.
func (e *adaptiveEntry) clearPreference() {
    e.preferred = ""
    e.verifiedFallback = ""
    e.plainReachable = false
    e.probeSeeded = false
    e.weakFailures = 0
    e.smallResponses = nil
}

// installVerifiedPreference is called only after the explicit site-run
// evidence gate. Reset preference-local state, but keep health for other
// methods; a freshly verified winner may clear its own cooldown.
func (e *adaptiveEntry) installVerifiedPreference(selected, backup string) {
    e.clearPreference()
    e.preferred=selected
    e.verifiedFallback=backup
    e.probeSeeded=selected!="pass"
    delete(e.cooldown,selected)
    delete(e.stalls,selected)
}

// A verified alternate is host-only TLS evidence from the same scan.
// Consume it once and never promote an unavailable or suspended method.
func (e *adaptiveEntry) retireWithFallback(host string, now time.Time, caps localdpi.Capabilities) string {
    backup:=e.verifiedFallback
    eligible:=e.probeSeeded && backup!="" && backup!=e.preferred && backup!="pass" &&
        host==adaptiveHostOnly(host) && nnHostTransport(host)==localdpi.TLS &&
        caps.Allows(localdpi.TLS,backup) && !now.Before(e.cooldown[backup])
    e.clearPreference()
    if eligible {return backup}
    return ""
}

type adaptiveSelector struct {
    capabilities localdpi.Capabilities
    candidates   [localdpi.QUIC + 1][]string
    neural       *adaptiveNeural
    mu sync.Mutex
    entries map[string]*adaptiveEntry
    selected map[string]struct{}
    generation uint64 // invalidates observations from old network sessions
    entryClock uint64
}

func newAdaptiveSelector(caps localdpi.Capabilities) *adaptiveSelector {
    selector := &adaptiveSelector{
        capabilities: caps,
        neural: &adaptiveNeural{},
        entries: make(map[string]*adaptiveEntry),
        generation: 1,
    }
    if caps.Kind() == localdpi.VPNSocket || caps.Kind() == localdpi.RootSocket {
        for _, transport := range []localdpi.Transport{localdpi.TLS, localdpi.HTTP, localdpi.QUIC} {
            selector.candidates[transport] = caps.Candidates(transport)
        }
    }
    return selector
}

var zapret2Auto = newAdaptiveSelector(socketCapabilities)

func validAdaptivePort(port string) bool {
    if len(port)==0 || len(port)>5 { return false }
    for _, c := range port { if c<'0' || c>'9' { return false } }
    n,err:=strconv.ParseUint(port,10,16)
    return err==nil && n>0
}

func canonicalAdaptiveHost(host string) string {
    host = strings.ToLower(strings.TrimSpace(host))
    // Normalize literals before interpreting a colon as port separation.
    if ip:=net.ParseIP(host);ip!=nil { return ip.String() }
    if strings.HasPrefix(host,"[") {
        literal:=host
        if strings.HasSuffix(host,"]") {
            literal=host[1:len(host)-1]
        } else {
            name,port,err:=net.SplitHostPort(host)
            if err!=nil || !validAdaptivePort(port) { return "" }
            literal=name
        }
        if ip:=net.ParseIP(literal);ip!=nil && strings.Contains(literal,":") { return ip.String() }
        return ""
    }
    if strings.Contains(host,":") {
        name,port,err:=net.SplitHostPort(host)
        if err!=nil || !validAdaptivePort(port) { return "" }
        host=name
    }
    host = strings.TrimSuffix(host,".")
    if ip:=net.ParseIP(host);ip!=nil { return ip.String() }
    if len(host)==0 || len(host)>253 { return "" }
    for _, label:=range strings.Split(host,".") {
        if len(label)==0 || len(label)>63 || label[0]=='-' || label[len(label)-1]=='-' { return "" }
        for _, c:=range label {
            if !(c>='a' && c<='z' || c>='0' && c<='9' || c=='-') { return "" }
        }
    }
    return host
}

// A live key may contain a concrete TCP peer after |. Never persist this
// address in neural sparse keys or reuse host-only probe evidence for it.
func adaptiveHostOnly(key string) string { return strings.SplitN(key, "|", 2)[0] }

// A TLS/QUIC first reply alone is insufficient for media/API targets.
func mediaAdaptiveHost(key string) bool {
    host := strings.TrimPrefix(strings.TrimPrefix(adaptiveHostOnly(key), "http:"), "udp:")
    for _, suffix := range []string{"youtube.com", "youtubei.googleapis.com", "googlevideo.com", "ytimg.com"} {
        if host == suffix || strings.HasSuffix(host, "."+suffix) { return true }
    }
    return false
}
func canonicalAdaptiveKey(key string) string {
    parts := strings.SplitN(key, "|", 2)
    raw := strings.ToLower(strings.TrimSpace(parts[0]))
    prefix := ""
    for _, p := range []string{"http:", "udp:"} {
        if strings.HasPrefix(raw,p) {
            prefix, raw = p, strings.TrimPrefix(raw,p)
            break
        }
    }
    // Normalize the destination, not the transport namespace. In particular
    // HTTP host:port and a literal QUIC IPv4 must not collapse into TLS keys.
    host := canonicalAdaptiveHost(raw)
    if host == "" { return "" }
    key = prefix + host
    if len(parts) == 1 { return key }
    ip := net.ParseIP(parts[1])
    if ip == nil { return "" }
    return key + "|" + ip.String()
}

// A suffix match is allowed only at a DNS-label boundary. User overrides
// for youtube.com therefore include *.youtube.com but never notyoutube.com.
func (a *adaptiveSelector) wants(host string) bool {
    host = canonicalAdaptiveHost(host)
    if host == "" { return false }
    a.mu.Lock()
    defer a.mu.Unlock()
    if _,ok:=a.selected[host];ok { return true }
    if net.ParseIP(host)!=nil { return false }
    for suffix := range a.selected {
        if net.ParseIP(suffix)==nil && strings.HasSuffix(host, "."+suffix) { return true }
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
        if host == "" { return errors.New("invalid Zapret2 adaptive host") }
        // Domain suffixes require a DNS name; IP literals match exactly.
        if net.ParseIP(host)==nil && !strings.Contains(host, ".") {
            return errors.New("adaptive host requires DNS name or IP")
        }
        list[host] = struct{}{}
        if len(list) > adaptiveMaxTargets { return errors.New("too many adaptive hosts") }
    }
    a.mu.Lock()
    a.selected = list
    a.resetLocked()
    a.mu.Unlock()
    return nil
}

func ConfigureZapret2AdaptiveHosts(text string) error { return zapret2Auto.configureHosts(text) }

// Each selection advances only for new TCP connections. The chosen strategy
// remains fixed for the lifetime of a TLS connection; changing its packet
// manipulation mid-stream would corrupt the TCP protocol.
func (a *adaptiveSelector) choose(host string) string {
    choice, _ := a.chooseWithGeneration(host, a.candidates[localdpi.TLS])
    return choice
}
func (a *adaptiveSelector) chooseTracked(host string) (string, uint64) {
    return a.chooseWithGeneration(host, a.candidates[localdpi.TLS])
}

// Plain HTTP/1 Host headers are eligible for legacy TCP tricks, but not
// TLS-record rewriting. A learned TLS-only winner must not disable
// desynchronization for a subsequent HTTP request to the same destination.
func (a *adaptiveSelector) chooseHTTPTracked(host string) (string, uint64) {
    // HTTP and TLS share a destination but not the same usable strategies.
    // Keep their live observations independent; HTTPS probe evidence stays
    // with the original TLS hostname.
    return a.chooseWithGeneration("http:"+host, a.candidates[localdpi.HTTP])
}

// QUIC evidence is separate and keyed by the protected UDP destination IP.
func (a *adaptiveSelector) chooseQUIC(host string) string {
    choice, _ := a.chooseQUICTracked(host)
    return choice
}
func (a *adaptiveSelector) chooseQUICTracked(host string) (string, uint64) {
    return a.chooseWithGeneration("udp:"+host, a.candidates[localdpi.QUIC])
}
func (a *adaptiveSelector) chooseFrom(host string, candidates []string) string {
    choice, _ := a.chooseWithGeneration(host, candidates)
    return choice
}

// Previous-network connections may close after a network reset. The captured
// generation prevents their late evidence changing the new network's winner.
func (a *adaptiveSelector) chooseWithGeneration(host string, candidates []string) (string, uint64) {
    choice, generation, _ := a.choosePolicy(host, candidates, false)
    return choice, generation
}

// Live traffic starts with the untouched transport. A received reply can
// retain this baseline without pretending that application content worked.
func (a *adaptiveSelector) chooseLive(host string, candidates []string) (string, uint64) {
    choice, generation, _ := a.choosePolicy(host, candidates, true)
    return choice, generation
}

// Capture the executor and cache entry while the network generation is held.
func (a *adaptiveSelector) chooseSocketLive(host string, transport localdpi.Transport) *adaptivePick {
    return a.chooseSocketAtGeneration(host, transport, 0)
}

func (a *adaptiveSelector) chooseSocketAtGeneration(host string, transport localdpi.Transport, dialGeneration uint64) *adaptivePick {
    host = canonicalAdaptiveKey(host)
    a.mu.Lock()
    defer a.mu.Unlock()

    if int(transport) >= len(a.candidates) || len(a.candidates[transport]) == 0 ||
        host != "" && nnHostTransport(host) != transport {
        return a.newSocketPick("", "", a.generation, transport)
    }
    // A transport created before a network change cannot advance or train
    // the new session. The direct baseline must still be admitted.
    if host == "" || dialGeneration != 0 && dialGeneration != a.generation {
        method := ""
        if a.capabilities.Allows(transport, "pass") {
            method = "pass"
        }
        return a.newSocketPick("", method, a.generation, transport)
    }
    choice, generation, entryID := a.choosePolicyLocked(host, a.candidates[transport], true)
    pick := a.newSocketPick(host, choice, generation, transport)
    pick.entryID = entryID
    return pick
}

// Diagnostic AUTO reads a private copy of the relevant live entry. Running
// the ordinary policy on the copy never advances the real cache or publishes
// a learnable flow identity. The neural ranker remains a read-only prior.
func (a *adaptiveSelector) chooseDiagnosticSocket(host string, transport localdpi.Transport) *adaptivePick {
    host=canonicalAdaptiveKey(host)
    a.mu.Lock()
    snapshot := &adaptiveSelector{
        capabilities: a.capabilities,
        candidates: a.candidates,
        neural: a.neural,
        generation: a.generation,
        entries: make(map[string]*adaptiveEntry),
    }
    if entry:=a.entries[host];entry!=nil {
        copyEntry:=*entry
        copyEntry.smallResponses=maps.Clone(entry.smallResponses)
        copyEntry.usage=maps.Clone(entry.usage)
        copyEntry.stalls=maps.Clone(entry.stalls)
        copyEntry.cooldown=maps.Clone(entry.cooldown)
        snapshot.entries[host]=&copyEntry
        snapshot.entryClock=entry.lastUsed
    }
    pick := snapshot.chooseSocketLive(host, transport)
    a.mu.Unlock()
    pick.owner = a
    pick.entryID = 0
    return pick
}

// entryLocked is the common admission path for live choices and explicit
// diagnostic preferences. Existing entries never trigger eviction. At the
// bound, remove just one least recently selected/seeded entry. Caller holds mu.
func (a *adaptiveSelector) entryLocked(host string) *adaptiveEntry {
    if a.entries == nil { a.entries = make(map[string]*adaptiveEntry) }
    e := a.entries[host]
    if e == nil {
        if len(a.entries) >= adaptiveMaxHosts {
            oldest := ""
            var oldestUse uint64
            for key, entry := range a.entries {
                if oldest == "" || entry.lastUsed < oldestUse ||
                    (entry.lastUsed == oldestUse && key < oldest) {
                    oldest, oldestUse = key, entry.lastUsed
                }
            }
            delete(a.entries, oldest)
        }
        e = &adaptiveEntry{}
        a.entries[host] = e
    }
    a.entryClock++
    if e.entryID == 0 { e.entryID = a.entryClock }
    e.lastUsed = a.entryClock
    return e
}

func (a *adaptiveSelector) choosePolicy(host string, candidates []string, directFirst bool) (string, uint64, uint64) {
    host = canonicalAdaptiveKey(host)
    a.mu.Lock()
    defer a.mu.Unlock()
    return a.choosePolicyLocked(host, candidates, directFirst)
}

func (a *adaptiveSelector) choosePolicyLocked(host string, candidates []string, directFirst bool) (string, uint64, uint64) {
    // A future executor may advertise no candidates, or no direct baseline.
    // Do not synthesize an unsupported method or divide by zero.
    if len(candidates)==0 { return "",a.generation,0 }
    hasPass := false
    for _,candidate:=range candidates { if candidate=="pass" { hasPass=true;break } }
    directFirst = directFirst && hasPass
    if host == "" { if directFirst { return "pass", a.generation, 0 }; return candidates[0], a.generation, 0 }
    e := a.entryLocked(host)
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
                return e.preferred, a.generation, e.entryID
            }
        }
        if blocked(e.preferred) {
            // The alternate was verified 3/3 on the same pinned addresses
            // during the same explicit scan. It remains scoped to this
            // host and generation; no retry within an existing TCP flow.
            fallback := e.retireWithFallback(host,now,a.capabilities)
            if fallback != "" {
                for _, candidate := range candidates {
                    if candidate == fallback {
                        e.preferred = fallback
                        e.probeSeeded = true
                        return fallback, a.generation, e.entryID
                    }
                }
            }
        }
    }
    if directFirst && e.index == 0 && !blocked("pass") {
        e.index++
        if e.usage == nil { e.usage = make(map[string]int) }
        e.usage["pass"]++
        return "pass", a.generation, e.entryID
    }
    // Preserve established candidate ordering and the plain baseline
    // unless an independent timeout-based circuit breaker is active.
    index := e.index
    if directFirst && index > 0 { index-- }
    tag := candidates[index%len(candidates)]
    available := false
    for offset := 0; offset < len(candidates); offset++ {
        choice := candidates[(index+offset)%len(candidates)]
        if !blocked(choice) {
            tag = choice
            available = true
            break
        }
    }
    // The optional locally generated MLP influences cold-start ordering only;
    // every fifth connection still explores the deterministic rotation.
    // A local neural prior must not suppress the plain TCP baseline.
    // Always try "pass" when its deterministic turn arrives, even with MLP.
    if available && tag != "pass" && e.index%5 != 4 {
        rankCandidates := candidates
        // Filter before ranking, otherwise a cooled highest score prevents
        // the model from considering its next eligible choice.
        if len(e.cooldown) != 0 {
            var scratch [8]string
            rankCandidates = scratch[:0]
            for _, candidate := range candidates {
                if !blocked(candidate) { rankCandidates = append(rankCandidates,candidate) }
            }
        }
        if ranked, ok := a.neural.rank(adaptiveHostOnly(host), rankCandidates, e.usage); ok {
            tag = ranked
        }
    }
    // If every candidate is cooled, keep deterministic rotation rather
    // than inventing a method or indefinitely starving a new connection.
    e.index++
    if e.usage == nil { e.usage = make(map[string]int) }
    if e.usage[tag] < 100 { e.usage[tag]++ }
    return tag, a.generation, e.entryID
}

// First real TCP reply is reachability only. Never train the MLP here.
func (a *adaptiveSelector) retainPlainReply(host string, generation uint64) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.generation != generation { return }
    a.retainPlainReplyLocked(host)
}

func (a *adaptiveSelector) retainPlainReplyLocked(host string) {
    e := a.entries[canonicalAdaptiveKey(host)]
    if e == nil { return }
    if e.preferred != "" && e.preferred != "pass" { return }
    if e.cooldown != nil && time.Now().Before(e.cooldown["pass"]) { return }
    if e.preferred != "pass" { e.clearPreference() }
    e.preferred = "pass"
    e.plainReachable = true
    e.probeSeeded = false
    e.verifiedFallback = ""
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
    a.observeStallLocked(host,strategy)
}

func (a *adaptiveSelector) observeStallLocked(host, strategy string) {
    host = canonicalAdaptiveKey(host)
    e := a.entries[host]
    if e == nil { return }
    if !a.capabilities.Allows(nnHostTransport(host),strategy) { return }
    if e.stalls == nil { e.stalls = make(map[string]int) }
    e.stalls[strategy]++
    if e.stalls[strategy] >= adaptiveStallThreshold {
        if e.cooldown == nil { e.cooldown = make(map[string]time.Time) }
        e.cooldown[strategy] = time.Now().Add(adaptiveStallCooldown)
        e.stalls[strategy] = 0
        if e.preferred == strategy {
            // Promote only a second profile that independently passed 3/3
            // HTTPS on every same-run pinned IP. Never use it for QUIC.
            if backup:=e.retireWithFallback(host,time.Now(),a.capabilities);backup!="" {
                e.preferred = backup
                e.probeSeeded = true
            }
        }
    }
    a.observeLocked(host, strategy, 0)
}

// Both network generation and cache incarnation must match under mu.
// An evicted flow cannot seed a later entry with the same destination key.
func (a *adaptiveSelector) socketPickCurrentLocked(pick *adaptivePick) bool {
    if !socketPickAdmissible(pick) || pick.owner != a || pick.entryID == 0 ||
        pick.flow.Generation != a.generation { return false }
    e := a.entries[canonicalAdaptiveKey(pick.host)]
    return e != nil && e.entryID == pick.entryID
}

func (a *adaptiveSelector) retainSocketReply(pick *adaptivePick) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if a.socketPickCurrentLocked(pick) && pick.flow.MethodID == "pass" {
        a.retainPlainReplyLocked(pick.host)
    }
}

func (a *adaptiveSelector) observeSocketEvidence(pick *adaptivePick, evidence localdpi.Evidence) {
    a.mu.Lock()
    defer a.mu.Unlock()
    if !a.socketPickCurrentLocked(pick) || !socketEvidenceAdmissible(pick,evidence) { return }
    switch evidence.Kind {
    case localdpi.Downstream:
        a.observeLocked(pick.host,pick.flow.MethodID,evidence.Bytes)
    case localdpi.FirstReplyTimeout:
        a.observeStallLocked(pick.host,pick.flow.MethodID)
    }
}

func (a *adaptiveSelector) observeLocked(host, strategy string, payloadBytes int64) {
    host = canonicalAdaptiveKey(host)
    // Validate at the mutation boundary too, not just at socket callers.
    if host=="" || payloadBytes<0 || !a.capabilities.Allows(nnHostTransport(host),strategy) { return }
    e := a.entries[host]
    if e == nil { return }
    // Meaningful downstream data clears previous timeout suspicions for
    // this exact host, transport and technique. Mere TCP dial success,
    // HTTP headers or a zero-byte Close never clears the circuit breaker.
    if payloadBytes >= adaptiveSmallResponseThreshold {
        if e.stalls != nil { delete(e.stalls, strategy) }
        if e.cooldown != nil { delete(e.cooldown, strategy) }
    }
    // An admitted observation can train only the model owned by this executor.
    a.neural.learn(adaptiveHostOnly(host), strategy, payloadBytes)
    if e.plainReachable && e.preferred == "pass" && strategy != "pass" { return }
    if payloadBytes >= adaptivePayloadThreshold {
        // A different candidate with a full-sized downstream flow may
        // supersede the HTML hint. The SAME verified candidate should not
        // lose its small-success threshold after one large response.
        if e.preferred != strategy {
            e.probeSeeded = false
            e.verifiedFallback = ""
            e.plainReachable = false
        }
        e.preferred = strategy
        e.weakFailures = 0
        e.smallResponses = nil
    } else if e.preferred == strategy {
        if strategy == "pass" && payloadBytes > 0 && !mediaAdaptiveHost(host) { e.weakFailures = 0; return }
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
                e.clearPreference()
                if strategy == "pass" && mediaAdaptiveHost(host) {
                    if e.cooldown == nil { e.cooldown = make(map[string]time.Time) }
                    e.cooldown["pass"] = time.Now().Add(adaptiveStallCooldown)
                }
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

// Reset all temporary knowledge when the network changes. Never persist
// the target's browsing history or the probe winner to preferences.
// Caller holds the selector lock. Configured targets are not transient.
func (a *adaptiveSelector) resetLocked() {
    a.entries = make(map[string]*adaptiveEntry)
    a.entryClock = 0
    a.generation++
}

func ResetZapret2AdaptiveLearning() {
    zapret2Auto.mu.Lock()
    defer zapret2Auto.mu.Unlock()
    zapret2Auto.resetLocked()
}
