//go:build linux

package bridge

import (
    "crypto/sha256"
    "encoding/hex"
    "os"
    "strings"
    "testing"
)

const expectedSeedSHA = "a9172f287e6bd4e6ac6ce5cdc3a606cf125b3ec3a8041ebd9ba59b12ac6d7a2b"

func loadTestNN(t *testing.T) []byte {
    t.Helper()
    // Test assets live in the repository, not inside the Android APK.
    raw, err := os.ReadFile("../../../models/zapret2-mlp-seed-v1.json")
    if err != nil { t.Fatalf("model source missing: %v", err) }
    sha := sha256.Sum256(raw)
    if hex.EncodeToString(sha[:]) != expectedSeedSHA { t.Fatal("pinned remote model SHA-256 changed") }
    return raw
}

func TestNeuralOptionalSeedShapeAndNoModelFallback(t *testing.T) {
    raw := loadTestNN(t)
    defer func() { _ = ConfigureZapret2NeuralModel(nil) }()
    if err := ConfigureZapret2NeuralModel(raw); err != nil { t.Fatal(err) }
    if got := zapret2Neural.weights; got == nil { t.Fatal("weights not installed") }
    s := newProbeAdaptiveSelector()
    if got := s.choose("www.youtube.com"); got != "tlsrec-split" {
        t.Fatalf("cold-start local TLS MLP choice: %q", got)
    }
    if got := s.choose("www.youtube.com"); got != "fake-5" {
        t.Fatalf("cold-start must explore other candidate: %q", got)
    }
    // A verified exact-host strategy always overrides the MLP prior.
    for i:=0; i<2; i++ { s.observeHTMLProbe("www.youtube.com", "plain", "timeout", 8000, s.generationSnapshot()) }
    for i:=0; i<2; i++ { s.observeHTMLProbe("www.youtube.com", "split", "ok", 600, s.generationSnapshot()) }
    if got := s.choose("www.youtube.com"); got != "split" {
        t.Fatalf("verified per-host winner must override neural prior: %q", got)
    }
    if err := ConfigureZapret2NeuralModel(nil); err != nil { t.Fatal(err) }
    normal := newProbeAdaptiveSelector()
    if got := normal.choose("www.youtube.com"); got != "split-1" {
        t.Fatalf("normal AUTO cannot require model: %q", got)
    }
}

func TestNeuralRejectsMalformedAndOversizedUntrustedWeights(t *testing.T) {
    raw := loadTestNN(t)
    for _, bad := range [][]byte{
        nil, []byte("[]"), []byte("null"), []byte("{}"),
        append(append([]byte{}, raw...), []byte("{}")...),
        []byte(strings.Repeat(" ", adaptiveNNMaxBytes+1)),
        []byte(strings.Replace(string(raw), "dppass-zapret2-mlp-v1", "bad", 1)),
        []byte(strings.Replace(string(raw), "[1,0,0,0,0,0]", "[7,0,0,0,0,0]", 1)),
        []byte(strings.Replace(string(raw), "\"output_bias\"", "\"unexpected_bias\"", 1)),
    } {
        if _, err := parseAdaptiveNN(bad); err == nil {
            t.Fatalf("accepted malformed neural model %q", string(bad[:min(90, len(bad))]))
        }
    }
    // Empty bytes are explicitly permitted to remove an installed model.
    if err := ConfigureZapret2NeuralModel(nil); err != nil { t.Fatal(err) }
}

func TestNeuralLearnsOnlyFromDecisiveLocalConnectionEvidence(t *testing.T) {
    raw := loadTestNN(t)
    if err := ConfigureZapret2NeuralModel(raw); err != nil { t.Fatal(err) }
    defer func() { _ = ConfigureZapret2NeuralModel(nil) }()
    host := "www.example.org"
    zapret2Neural.mu.Lock()
    start, _ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    zapret2Neural.learn(host, "tlsrec-split", 1024) // too little: inconclusive
    zapret2Neural.mu.Lock()
    afterWeak, _ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if start != afterWeak { t.Fatal("small control packet trained NN") }
    for i:=0; i<5; i++ {
        zapret2Neural.learn(host, "tlsrec-split", adaptivePayloadThreshold)
    }
    zapret2Neural.mu.Lock()
    afterSuccess, _ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if afterSuccess <= start { t.Fatal("success did not increase action value") }
    for i:=0; i<8; i++ {
        zapret2Neural.learn(host, "tlsrec-split", 0)
    }
    zapret2Neural.mu.Lock()
    afterFailure, _ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if afterFailure >= afterSuccess { t.Fatal("zero downstream connections did not reduce value") }
}
