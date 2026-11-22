//go:build linux

package bridge

import "testing"

func newProbeAdaptiveSelector() *adaptiveSelector {
    return &adaptiveSelector{
        entries: make(map[string]*adaptiveEntry),
        selected: make(map[string]struct{}),
    }
}

func TestAutoLearnsVerifiedYouTubeHTMLButNotRedirectOrPartial(t *testing.T) {
    a := newProbeAdaptiveSelector()
    const host = "www.youtube.com"
    generation := a.generationSnapshot()
    a.observeHTMLProbe(host, "plain", "timeout", 8000, generation)
    a.observeHTMLProbe(host, "plain", "timeout", 8000, generation)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1000, generation)
    if got := a.choose(host); got != "split-1" {
        t.Fatalf("one successful probe must not pin: %s", got)
    }
    a.observeHTMLProbe(host, "tlsrec-split", "redirect", 200, generation)
    if got := a.choose(host); got != "split" {
        t.Fatalf("a redirect must not pin: %s", got)
    }
    // A fresh run resets prior 1/2 or redirect evidence.
    a.observeHTMLProbe(host, "plain", "timeout", 8000, generation)
    a.observeHTMLProbe(host, "plain", "timeout", 8000, generation)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 934, generation)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1118, generation)
    for i := 0; i < 2; i++ {
        if got := a.choose(host); got != "tlsrec-split" {
            t.Fatalf("verified YouTube HTML should teach AUTO: %s", got)
        }
    }
    if got := a.choose("youtube.com"); got != "split-1" {
        t.Fatalf("exact-host evidence incorrectly spread to parent: %s", got)
    }
    if got := a.choose("i.ytimg.com"); got != "split-1" {
        t.Fatalf("HTML evidence incorrectly spread to thumbnail CDN: %s", got)
    }
    if got := a.choose("r1.googlevideo.com"); got != "split-1" {
        t.Fatalf("HTML evidence incorrectly spread to streaming CDN: %s", got)
    }
}

func TestAutoProbePreferenceSurvivesShortSuccessfulPagesButFallsBack(t *testing.T) {
    a := newProbeAdaptiveSelector()
    const host = "www.youtube.com"
    g := a.generationSnapshot()
    for i := 0; i < 2; i++ {
        a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
        a.observeHTMLProbe(host, "tlsrec-split", "ok", 1000, g)
    }
    // The real probe reads at most 8 KiB. It must not erase the preference.
    a.observe(host, "tlsrec-split", 8192)
    a.observe(host, "tlsrec-split", 8192)
    if got := a.choose(host); got != "tlsrec-split" {
        t.Fatalf("8 KiB verified-page traffic must preserve selected method: %s", got)
    }
    a.observe(host, "tlsrec-split", 0)
    if got := a.choose(host); got != "tlsrec-split" {
        t.Fatalf("one blank connection is insufficient to unpin: %s", got)
    }
    a.observe(host, "tlsrec-split", 0)
    if got := a.choose(host); got != "fake-5" {
        t.Fatalf("expected rotation toward alternate candidate after two failed flows: %s", got)
    }
}

func TestAutoPrefersFasterVerifiedMethodOnlyAfterTwoSuccesses(t *testing.T) {
    a := newProbeAdaptiveSelector()
    g := a.generationSnapshot()
    const host = "www.youtube.com"
    a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
    a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 934, g)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1118, g)
    a.observeHTMLProbe(host, "fake-5", "ok", 1202, g)
    a.observeHTMLProbe(host, "fake-5", "ok", 1474, g)
    if got := a.choose(host); got != "tlsrec-split" {
        t.Fatalf("slower method must not overwrite verified winner: %s", got)
    }
    a.observeHTMLProbe(host, "split", "ok", 300, g)
    if got := a.choose(host); got != "tlsrec-split" {
        t.Fatalf("one fast trial is not enough: %s", got)
    }
    a.observeHTMLProbe(host, "split", "ok", 400, g)
    if got := a.choose(host); got != "split" {
        t.Fatalf("two faster verified trials should win: %s", got)
    }
}

func TestAutoDoesNotPromoteWhenBaselineHasVerifiedContent(t *testing.T) {
    a := newProbeAdaptiveSelector()
    const host = "www.youtube.com"
    g := a.generationSnapshot()
    a.observeHTMLProbe(host, "plain", "ok", 500, g)
    a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1000, g)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1000, g)
    if got := a.choose(host); got != "split-1" {
        t.Fatalf("baseline accessible; no bypass should be trained: %s", got)
    }
}

func TestAutoIgnoresStaleNetworkAndWrongHostProbeEvidence(t *testing.T) {
    a := newProbeAdaptiveSelector()
    gen := a.generationSnapshot()
    if err := a.configureHosts("youtube.com"); err != nil { t.Fatal(err) }
    for i := 0; i < 2; i++ {
        a.observeHTMLProbe("www.youtube.com", "plain", "timeout", 8000, gen)
        a.observeHTMLProbe("www.youtube.com", "tlsrec-split", "ok", 1000, gen)
    }
    if got := a.choose("www.youtube.com"); got != "split-1" {
        t.Fatalf("previous session poisoned new network: %s", got)
    }
    current := a.generationSnapshot()
    for i := 0; i < 2; i++ {
        a.observeHTMLProbe("www.google.com", "plain", "timeout", 8000, current)
        a.observeHTMLProbe("www.google.com", "tlsrec-split", "ok", 1000, current)
        a.observeHTMLProbe("i.ytimg.com", "plain", "timeout", 8000, current)
        a.observeHTMLProbe("i.ytimg.com", "fake-5", "ok", 1000, current)
    }
    if got := a.choose("www.google.com"); got != "split-1" { t.Fatal("Google HTML poisoned AUTO") }
    if got := a.choose("i.ytimg.com"); got != "split-1" { t.Fatal("thumbnail poisoned AUTO") }
}

func TestAutoRejectsOneOfTwoSuccessfulOrInvalidProbeOutcomes(t *testing.T) {
    a := newProbeAdaptiveSelector()
    g := a.generationSnapshot()
    const host = "www.youtube.com"
    a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
    a.observeHTMLProbe(host, "plain", "timeout", 8000, g)
    a.observeHTMLProbe(host, "fake-5", "ok", 1000, g)
    a.observeHTMLProbe(host, "fake-5", "timeout", 8000, g)
    a.observeHTMLProbe(host, "auto", "ok", 1000, g)
    a.observeHTMLProbe(host, "fake-123", "ok", 1000, g)
    a.observeHTMLProbe(host, "tlsrec-split", "content_invalid", 1000, g)
    a.observeHTMLProbe(host, "tlsrec-split", "ok", 1000, g)
    if got := a.choose(host); got != "split-1" {
        t.Fatalf("partial, AUTO, invalid and 1/2 results must not pin: %s", got)
    }
}
