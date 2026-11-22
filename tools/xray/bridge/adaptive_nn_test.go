//go:build linux

package bridge

import (
    "encoding/json"
    "math"
    "strings"
    "testing"
)

// Construct the same schema Android generates, without any downloadable
// seed or pretrained assets. A large local model must remain bounded.
func generatedTestModel(t *testing.T, hidden int) []byte {
    t.Helper()
    w := adaptiveNNWeights{
        Format: "dppass-zapret2-mlp-v2",
        Hidden: make([][]float64, hidden),
        Bias: make([]float64, hidden),
        Output: make([][]float64, adaptiveNNOutput),
        OutputBias: make([]float64, adaptiveNNOutput),
    }
    for i := range w.Hidden {
        w.Hidden[i] = make([]float64, adaptiveNNInput)
        w.Hidden[i][i % adaptiveNNInput] = 1
    }
    for i := range w.Output { w.Output[i] = make([]float64, hidden) }
    // TLS-record and QUIC pass can be favored as a pure cold-start prior.
    w.Output[5][0] = 0.5
    w.Output[8][2] = 0.25
    raw, err := json.Marshal(w)
    if err != nil { t.Fatal(err) }
    return raw
}

func TestOptionalNeuralSizedLocalGenerationAndBaseline(t *testing.T) {
    defer func() { _ = ConfigureZapret2NeuralModel(nil) }()
    if err := ConfigureZapret2NeuralModel(nil); err != nil { t.Fatal(err) }
    a := newProbeAdaptiveSelector()
    if got := a.choose("www.youtube.com"); got != "split-1" {
        t.Fatalf("built-in AUTO missing: %s", got)
    }
    for _, width := range []int{32,128,512,1024} {
        raw := generatedTestModel(t, width)
        if err := ConfigureZapret2NeuralModel(raw); err != nil {
            t.Fatalf("size %d: %v (length %d)", width, err, len(raw))
        }
        if len(zapret2Neural.weights.Hidden) != width { t.Fatal("wrong model dimension") }
    }
    a = newProbeAdaptiveSelector()
    if got := a.choose("www.youtube.com"); got != "tlsrec-split" {
        t.Fatalf("local model not active: %s", got)
    }
    // The repeated-host observation count must allow exploration, not pin an
    // untrained prior forever. A verified exact-host preference outranks MLP.
    g := a.generationSnapshot()
    for i:=0;i<2;i++ { a.observeHTMLProbe("www.youtube.com", "plain", "timeout", 8000, g) }
    for i:=0;i<2;i++ { a.observeHTMLProbe("www.youtube.com", "fake-5", "ok", 1100, g) }
    if got := a.choose("www.youtube.com"); got != "fake-5" {
        t.Fatalf("probe winner must override model: %s", got)
    }
    _ = ConfigureZapret2NeuralModel(nil)
    a = newProbeAdaptiveSelector()
    if got := a.choose("www.youtube.com"); got != "split-1" { t.Fatal(got) }
}

func TestNeuralRejectsMalformedAndOversizedUntrustedWeights(t *testing.T) {
    raw := generatedTestModel(t, 32)
    for _, bad := range [][]byte{
        []byte("[]"), []byte("{}"), []byte("null"),
        append(append([]byte{}, raw...), []byte("{}")...),
        []byte(strings.Repeat(" ", adaptiveNNMaxBytes+1)),
        []byte(strings.Replace(string(raw), "dppass-zapret2-mlp-v2", "bad", 1)),
        []byte(strings.Replace(string(raw), "[1,0,0,0,0,0,0,0]", "[7,0,0,0,0,0,0,0]", 1)),
        []byte(strings.Replace(string(raw), "\"output_bias\"", "\"unknown_bias\"", 1)),
        generatedTestModel(t, 7),
        generatedTestModel(t, 1025),
    } {
        if _, err := parseAdaptiveNN(bad); err == nil {
            t.Fatalf("accepted invalid model: %q", string(bad[:min(70, len(bad))]))
        }
    }
}

func TestNeuralLearnsFromLocalTrafficOnly(t *testing.T) {
    if err := ConfigureZapret2NeuralModel(generatedTestModel(t, 128)); err != nil { t.Fatal(err) }
    defer func(){ _=ConfigureZapret2NeuralModel(nil) }()
    host := "www.example.org"
    zapret2Neural.mu.Lock()
    start,_ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    zapret2Neural.learn(host, "tlsrec-split", 1024)
    zapret2Neural.mu.Lock()
    afterWeak,_ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if start != afterWeak { t.Fatal("inconclusive bytes trained model") }
    for i:=0;i<5;i++ { zapret2Neural.learn(host, "tlsrec-split", adaptivePayloadThreshold) }
    zapret2Neural.mu.Lock()
    afterSuccess,_ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if afterSuccess <= start { t.Fatal("traffic success failed to raise estimate") }
    for i:=0;i<8;i++ { zapret2Neural.learn(host, "tlsrec-split", 0) }
    zapret2Neural.mu.Lock()
    afterFail,_ := nnForward(zapret2Neural.weights, host, 5, false)
    zapret2Neural.mu.Unlock()
    if afterFail >= afterSuccess { t.Fatal("empty downstream did not lower estimate") }
}

func TestNeuralNetworkClassFeaturesCannotLeakCarrierIdentity(t *testing.T) {
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    f:=nnFeatures("www.youtube.com",false)
    if f[6]!=1 || f[7]!=0 {t.Fatal(f)}
    if err:=ConfigureZapret2NeuralNetwork("WIFI");err!=nil {t.Fatal(err)}
    f=nnFeatures("www.youtube.com",false)
    if f[6]!=0 || f[7]!=1 {t.Fatal(f)}
    if err:=ConfigureZapret2NeuralNetwork("carrier-name");err==nil {t.Fatal("carrier identity accepted")}
    if err:=ConfigureZapret2NeuralNetwork("UNKNOWN");err!=nil {t.Fatal(err)}
    f=nnFeatures("www.youtube.com",false)
    if math.Abs(f[6])+math.Abs(f[7])!=0 {t.Fatal(f)}
}
