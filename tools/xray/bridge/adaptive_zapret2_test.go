//go:build linux

package bridge

import (
    "strconv"
    "testing"
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
