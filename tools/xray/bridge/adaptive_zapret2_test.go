//go:build linux

package bridge

import (
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
        _ = a.choose("prefix"+string(rune('a'+i%26))+".example.com")
    }
    if len(a.entries) > adaptiveMaxHosts { t.Fatal("unbounded host cache") }
}

func TestAdaptiveParseTag(t *testing.T) {
    mode,ok,err:=parseDesyncTag("dppass:exp-auto")
    if !ok || err!=nil || mode.kind!=desyncAuto { t.Fatalf("auto strategy: %v %v %+v",ok,err,mode) }
}
