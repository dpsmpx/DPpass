//go:build linux

package bridge

import (
    "net"
    "strconv"
    "testing"
    "time"
)

func TestAdaptiveRotatesPerHostUntilEnoughPayload(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    if got := a.choose("r1.googlevideo.com"); got != "split-1" { t.Fatalf("first: %q", got) }
    if got := a.choose("r1.googlevideo.com"); got != "split" { t.Fatalf("second: %q", got) }
    if got := a.choose("i.ytimg.com"); got != "split-1" { t.Fatalf("different host: %q", got) }
    a.observe("r1.googlevideo.com", "split", 3*1024) // TLS/headers alone are not proof
    if got := a.choose("r1.googlevideo.com"); got != "fake-3" { t.Fatalf("partial media load must not pin: %q", got) }
    a.observe("r1.googlevideo.com", "fake-3", 128*1024)
    for i := 0; i < 3; i++ {
        if got := a.choose("r1.googlevideo.com"); got != "fake-3" { t.Fatalf("verified payload must pin winner: %q", got) }
    }
    a.observe("r1.googlevideo.com", "fake-3", 2*1024)
    if got := a.choose("r1.googlevideo.com"); got != "fake-3" { t.Fatalf("single short request shouldn't discard winner: %q", got) }
    a.observe("r1.googlevideo.com", "fake-3", 0)
    if got := a.choose("r1.googlevideo.com"); got == "fake-3" { t.Fatalf("two failed flows should rotate: %q", got) }
}

func TestAdaptiveHostSelectionsRespectDNSLabelBoundary(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    if err := a.configureHosts("YouTube.com\nytimg.com\n"); err != nil { t.Fatal(err) }
    for _, h := range []string{"youtube.com", "www.youtube.com", "I.YTIMG.com"} {
        if !a.wants(h) { t.Errorf("missing suffix match for %s", h) }
    }
    for _, h := range []string{"fakeyoutube.com", "youtube.com.attacker.test", "example.com"} {
        if a.wants(h) { t.Errorf("incorrect wildcard override %s", h) }
    }
    if err := a.configureHosts("valid.example\nbad host"); err == nil { t.Fatal("invalid host accepted") }
    if !a.wants("www.youtube.com") { t.Fatal("invalid update must preserve previous selection") }
}

func TestAdaptiveDoesNotStoreUnboundedHostHistory(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    for i:=0; i<adaptiveMaxHosts*2; i++ {
        _ = a.choose("prefix"+strconv.Itoa(i)+".example.com")
    }
    if len(a.entries) > adaptiveMaxHosts { t.Fatal("unbounded host cache") }
}

func TestAdaptiveParseTag(t *testing.T) {
    mode,ok,err:=parseDesyncTag("dppass:exp-auto")
    if !ok || err!=nil || mode.kind!=desyncAuto { t.Fatalf("auto strategy: %v %v %+v",ok,err,mode) }
}

func TestAdaptiveQuicSelectionIsIndependentOfTCP(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    if got := a.choose("203.0.113.9"); got != "split-1" { t.Fatal(got) }
    if got := a.chooseQUIC("203.0.113.9"); got != "fake-3" { t.Fatal(got) }
    if got := a.chooseQUIC("203.0.113.9"); got != "fake-5" { t.Fatal(got) }
    a.observe("udp:203.0.113.9", "fake-5", 512*1024)
    if got := a.chooseQUIC("203.0.113.9"); got != "fake-5" { t.Fatal("QUIC preference not retained", got) }
    if got := a.choose("203.0.113.9"); got != "split" { t.Fatal("QUIC must not change TCP selection", got) }
}

func TestAdaptiveLearnsSmallFeedResponsesOnlyAfterMultipleFlows(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "www.youtube.com"
    for i := 0; i < len(adaptiveCandidates)*3; i++ {
        choice := a.choose(host)
        // Other strategies only reach TLS/metadata; this candidate reliably
        // carries substantial short feed responses.
        if choice == "split" {
            a.observe(host, choice, adaptiveSmallResponseThreshold+1024)
        } else {
            a.observe(host, choice, 2048)
        }
    }
    for i := 0; i < 3; i++ {
        if got := a.choose(host); got != "split" { t.Fatalf("weak repeated payload preference: %q", got) }
    }
}

func TestAdaptiveIgnoresLateOldNetworkObservations(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "r1.googlevideo.com"
    choice, oldGeneration := a.chooseTracked(host)
    if err := a.configureHosts("youtube.com"); err != nil { t.Fatal(err) }
    if got := a.choose(host); got != "split-1" { t.Fatal(got) }
    a.observeTracked(host, choice, adaptivePayloadThreshold*2, oldGeneration)
    if got := a.choose(host); got != "split" {
        t.Fatalf("old carrier response poisoned new network: %q", got)
    }
}

func TestAdaptiveManualIPv4TargetCoversQUIC(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    if err := a.configureHosts("203.0.113.9"); err != nil { t.Fatal(err) }
    if !a.wants("203.0.113.9") { t.Fatal("selected IP must apply to protected QUIC destination") }
    if a.wants("203.0.113.10") { t.Fatal("selection must not cover unrelated IP") }
}


// The new lossless TLS-record/TCP method is tried only after the existing
// five candidates; users' explicit manual choices are not rewritten.
func TestAdaptiveIncludesCombinedTLSRecordSplitWithoutReorderingLegacyCandidates(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    want := []string{"split-1", "split", "fake-3", "fake-5", "disorder", "tlsrec-split"}
    for i, expected := range want {
        if got := a.choose("video.example.org"); got != expected {
            t.Fatalf("rotation %d got %q want %q", i, got, expected)
        }
    }
    a.observe("video.example.org", "tlsrec-split", adaptivePayloadThreshold)
    if got := a.choose("video.example.org"); got != "tlsrec-split" {
        t.Fatalf("new mode cannot earn adaptive preference: %q", got)
    }
}


func TestAdaptiveHTTPNeverUsesTLSRecordOnlyCandidate(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "video.example.org"
    // Even when a TLS connection taught this host a successful TLS-record
    // preference, an HTTP/1 Host request must use a legacy HTTP strategy.
    a.chooseTracked(host)
    a.observe(host, "tlsrec-split", adaptivePayloadThreshold)
    for i := 0; i < 12; i++ {
        got, _ := a.chooseHTTPTracked(host)
        if got == "tlsrec-split" { t.Fatal("TLS-record-only mode selected for HTTP") }
    }
}

// An adaptive QUIC flow must be able to recover by using unmodified QUIC.
// This does not alter manually configured fake-3/fake-5 or QUIC-to-TCP.
func TestAdaptiveQUICIncludesUnmodifiedBaselineAfterExistingCandidates(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "198.51.100.23"
    for _, want := range []string{"fake-3", "fake-5", "pass"} {
        if got := a.chooseQUIC(host); got != want { t.Fatalf("want %s, got %s", want, got) }
    }
    a.observe("udp:"+host, "pass", adaptivePayloadThreshold)
    for i := 0; i < 3; i++ {
        if got := a.chooseQUIC(host); got != "pass" { t.Fatalf("QUIC baseline preference lost: %s", got) }
    }
    if got := a.choose(host); got != "split-1" { t.Fatalf("QUIC selection changed TCP: %s", got) }
}

func TestAdaptiveTCPPlainBaselineFollowsLegacyStrategies(t *testing.T) {
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "video.example.org"
    for _, want := range []string{"split-1", "split", "fake-3", "fake-5", "disorder", "tlsrec-split", "pass"} {
        if got := a.choose(host); got != want { t.Fatalf("got %q, expected %q", got, want) }
    }
    a.observe(host, "pass", adaptivePayloadThreshold)
    if got := a.choose(host); got != "pass" { t.Fatalf("plain TCP should be learnable: %q", got) }
    for _, want := range []string{"split-1", "split", "fake-3", "fake-5", "disorder", "pass"} {
        if got, _ := a.chooseHTTPTracked("feeds.example.org"); got != want {
            t.Fatalf("HTTP candidate %q, expected %q", got, want)
        }
    }
}

func TestAdaptiveTCPFirstReplyTimeoutNotDoubleCountedOnClose(t *testing.T) {
    if err := zapret2Auto.configureHosts(""); err != nil { t.Fatal(err) }
    t.Cleanup(func() { _ = zapret2Auto.configureHosts("") })
    host := "timeout-test.example.org"
    strategy, generation := zapret2Auto.chooseTracked(host)
    zapret2Auto.observeTracked(host, strategy, adaptivePayloadThreshold, generation)
    for flow := 0; flow < 2; flow++ {
        listener, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
        if err != nil { t.Fatal(err) }
        client, err := net.DialTCP("tcp", nil, listener.Addr().(*net.TCPAddr))
        if err != nil { listener.Close(); t.Fatal(err) }
        peer, err := listener.AcceptTCP()
        if err != nil { client.Close(); listener.Close(); t.Fatal(err) }
        // Simulate a previously sent ClientHello and a server that never
        // replies. No real DPI planner or external endpoint is involved.
        conn := &desyncConn{TCPConn: client, firstDone: true}
        conn.stageHelloSent.Store(true)
        conn.adaptiveSelection.Store(&adaptivePick{host: host, strategy: strategy, generation: generation})
        if err := client.SetReadDeadline(time.Now().Add(-time.Millisecond)); err != nil { t.Fatal(err) }
        if _, err := conn.Read(make([]byte, 8)); !isZapret2Timeout(err) {
            t.Fatalf("expected a timeout, got %v", err)
        }
        if err := conn.Close(); err != nil { t.Fatal(err) }
        peer.Close()
        listener.Close()
        zapret2Auto.mu.Lock()
        entry := zapret2Auto.entries[host]
        preferred, failures := entry.preferred, entry.weakFailures
        zapret2Auto.mu.Unlock()
        if flow == 0 && (preferred != strategy || failures != 1) {
            t.Fatalf("timeout and Close duplicated failure: preferred=%q failures=%d", preferred, failures)
        }
        if flow == 1 && preferred != "" {
            t.Fatalf("two stalled connections should release the pinned strategy: %q", preferred)
        }
    }
}

func TestAdaptivePlainTCPTriedWithLocalNeuralModel(t *testing.T) {
    if err := ConfigureZapret2NeuralModel(generatedTestModel(t, 32)); err != nil { t.Fatal(err) }
    defer func() { _ = ConfigureZapret2NeuralModel(nil) }()
    a := &adaptiveSelector{entries: make(map[string]*adaptiveEntry), selected: make(map[string]struct{})}
    host := "new.example.org"
    for i := 0; i < len(adaptiveCandidates); i++ {
        got := a.choose(host)
        if i == len(adaptiveCandidates)-1 && got != "pass" {
            t.Fatalf("local MLP suppressed the TCP baseline: %q", got)
        }
    }
    for i := 0; i < len(adaptiveHTTPCandidates); i++ {
        got, _ := a.chooseHTTPTracked(host)
        if i == len(adaptiveHTTPCandidates)-1 && got != "pass" {
            t.Fatalf("local MLP suppressed the HTTP baseline: %q", got)
        }
    }
}

func TestUniversalAUTOStallsOnlySuspendAffectedHostTechnique(t *testing.T) {
    a:=&adaptiveSelector{entries:make(map[string]*adaptiveEntry),selected:make(map[string]struct{})}
    host:="media.example.net"
    selected,generation:=a.chooseTracked(host)
    if selected!="split-1" {t.Fatalf("unexpected initial choice %s",selected)}
    a.observeStallTracked(host,selected,generation)
    if len(a.entries[host].cooldown)!=0 {
        t.Fatal("one stalled TLS handshake must not cause a circuit breaker")
    }
    a.observeStallTracked(host,selected,generation)
    if !time.Now().Before(a.entries[host].cooldown[selected]) {
        t.Fatal("second first-reply timeout did not suspend the method")
    }
    if got:=a.choose(host);got!="split" {
        t.Fatalf("cooldown blocked other methods for same host: %s",got)
    }
    if got:=a.choose("another.example.net");got!="split-1" {
        t.Fatalf("cooldown leaked to unrelated host: %s",got)
    }
    for i:=0;i<15;i++ {
        if got:=a.choose(host);got==selected {
            t.Fatalf("cooled method returned early on iteration %d",i)
        }
    }
    a.entries[host].cooldown[selected]=time.Now().Add(-time.Millisecond)
    a.entries[host].index=0
    if got:=a.choose(host);got!=selected {
        t.Fatalf("expired cooldown failed to restore candidate: %s",got)
    }
}

func TestUniversalAUTONetworkTransportAndCloseAreIsolated(t *testing.T) {
    a:=&adaptiveSelector{entries:make(map[string]*adaptiveEntry),selected:make(map[string]struct{})}
    host:="203.0.113.10"
    picked,generation:=a.chooseQUICTracked(host)
    if picked!="fake-3" {t.Fatal(picked)}
    a.observeStallTracked("udp:"+host,picked,generation)
    a.observeStallTracked("udp:"+host,picked,generation)
    if got:=a.chooseQUIC(host);got!="fake-5" {
        t.Fatalf("QUIC timeout did not skip only the affected UDP method: %s",got)
    }
    if got:=a.choose(host);got!="split-1" {
        t.Fatalf("QUIC cooldown leaked into TCP: %s",got)
    }
    other:="close.example.net"
    choice,g:=a.chooseTracked(other)
    a.observeTracked(other,choice,0,g) // normal early Close isn't necessarily a timeout
    a.observeTracked(other,choice,0,g)
    if a.entries[other].cooldown!=nil {
        t.Fatal("normal Close poisoned AUTO even without a timed-out ClientHello")
    }
    old:=a.generationSnapshot()
    if err:=a.configureHosts("youtube.com");err!=nil {t.Fatal(err)}
    fresh:="fresh.example.net"
    first,_:=a.chooseTracked(fresh)
    a.observeStallTracked(fresh,first,old)
    a.observeStallTracked(fresh,first,old)
    if len(a.entries[fresh].cooldown)!=0 {
        t.Fatal("old-network failures contaminated the current network")
    }
}

func TestUniversalAUTORealPayloadClearsOnlyMatchingCircuitBreaker(t *testing.T) {
    a:=&adaptiveSelector{entries:make(map[string]*adaptiveEntry),selected:make(map[string]struct{})}
    host:="example.org"
    first,g:=a.chooseTracked(host)
    a.observeStallTracked(host,first,g)
    a.observeStallTracked(host,first,g)
    if len(a.entries[host].cooldown)!=1 {t.Fatal("missing stall cooldown")}
    a.observeTracked(host,"split",adaptiveSmallResponseThreshold,g)
    if len(a.entries[host].cooldown)!=1 {
        t.Fatal("unrelated strategy success cleared another method cooldown")
    }
    a.observeTracked(host,first,adaptiveSmallResponseThreshold,g)
    if len(a.entries[host].cooldown)!=0 || a.entries[host].stalls[first]!=0 {
        t.Fatal("meaningful response should restore just the matching strategy")
    }
}
