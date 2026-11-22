//go:build linux

package bridge

// Optional 6-6-9 tiny MLP for cold-start strategy ordering. The weights are
// NOT bundled in the APK. Android explicitly downloads a pinned JSON file,
// validates SHA-256 and installs it into app-private storage. Inference,
// online gradient updates and all connection observations stay on-device.
// No domain/IP/packet body is exported or written to the model file.
import (
    "bytes"
    "encoding/json"
    "errors"
    "io"
    "math"
    "net"
    "strings"
    "sync"
)

const (
    adaptiveNNInput = 6
    adaptiveNNHidden = 6
    adaptiveNNOutput = 9 // 6 TCP + 3 QUIC candidate positions
    adaptiveNNMaxBytes = 4096
)

type adaptiveNNWeights struct {
    Format string `json:"format"`
    Hidden [][]float64 `json:"hidden"`
    Bias []float64 `json:"bias"`
    Output [][]float64 `json:"output"`
    OutputBias []float64 `json:"output_bias"`
}

type adaptiveNeural struct {
    mu sync.Mutex
    weights *adaptiveNNWeights
}
var zapret2Neural adaptiveNeural

func validNNNumber(x float64) bool { return !math.IsNaN(x) && !math.IsInf(x, 0) && math.Abs(x) <= 4 }

func parseAdaptiveNN(raw []byte) (*adaptiveNNWeights, error) {
    if len(raw) == 0 || len(raw) > adaptiveNNMaxBytes { return nil, errors.New("invalid neural model length") }
    var w adaptiveNNWeights
    decoder := json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&w); err != nil { return nil, errors.New("invalid neural model JSON") }
    var extra json.RawMessage
    if err := decoder.Decode(&extra); err != io.EOF {
        return nil, errors.New("trailing neural model content")
    }
    if w.Format != "dppass-zapret2-mlp-v1" ||
        len(w.Hidden) != adaptiveNNHidden || len(w.Bias) != adaptiveNNHidden ||
        len(w.Output) != adaptiveNNOutput || len(w.OutputBias) != adaptiveNNOutput {
        return nil, errors.New("unsupported neural model dimensions")
    }
    for i := range w.Hidden {
        if len(w.Hidden[i]) != adaptiveNNInput { return nil, errors.New("bad hidden matrix") }
        for _, n := range w.Hidden[i] { if !validNNNumber(n) { return nil, errors.New("bad hidden weight") } }
        if !validNNNumber(w.Bias[i]) { return nil, errors.New("bad hidden bias") }
    }
    for i := range w.Output {
        if len(w.Output[i]) != adaptiveNNHidden { return nil, errors.New("bad output matrix") }
        for _, n := range w.Output[i] { if !validNNNumber(n) { return nil, errors.New("bad output weight") } }
        if !validNNNumber(w.OutputBias[i]) { return nil, errors.New("bad output bias") }
    }
    return &w, nil
}

// Empty bytes explicitly disable the optional model; the deterministic
// adaptive selector remains available even if the user never downloads it.
func ConfigureZapret2NeuralModel(raw []byte) error {
    if len(raw) == 0 {
        zapret2Neural.mu.Lock()
        zapret2Neural.weights = nil
        zapret2Neural.mu.Unlock()
        return nil
    }
    w, err := parseAdaptiveNN(raw)
    if err != nil { return err }
    zapret2Neural.mu.Lock()
    zapret2Neural.weights = w
    zapret2Neural.mu.Unlock()
    return nil
}

func nnCandidateIndex(tag string, quic bool) int {
    if quic {
        for i, candidate := range adaptiveQuicCandidates {
            if tag == candidate { return len(adaptiveCandidates) + i }
        }
        return -1
    }
    for i, candidate := range adaptiveCandidates {
        if tag == candidate { return i }
    }
    return -1
}

func nnFeatures(host string, quic bool) [adaptiveNNInput]float64 {
    var f [adaptiveNNInput]float64
    raw := host
    if quic {
        f[2] = 1
        raw = strings.TrimPrefix(raw, "udp:")
    } else if strings.HasPrefix(raw, "http:") {
        f[1] = 1
        raw = strings.TrimPrefix(raw, "http:")
    } else {
        f[0] = 1
    }
    parsed := net.ParseIP(strings.Trim(raw, "[]"))
    if parsed != nil && parsed.To4() == nil { f[3] = 1 }
    if parsed == nil && strings.Contains(raw, ".") { f[4] = 1 }
    if strings.HasSuffix(raw, ".googlevideo.com") { f[5] = 1 }
    return f
}

func nnForward(w *adaptiveNNWeights, host string, idx int, quic bool) (float64, [adaptiveNNHidden]float64) {
    f := nnFeatures(host, quic)
    var h [adaptiveNNHidden]float64
    for i := range h {
        sum := w.Bias[i]
        for j, v := range f { sum += w.Hidden[i][j] * v }
        h[i] = math.Max(0, sum) // ReLU
    }
    value := w.OutputBias[idx]
    for j, v := range h { value += w.Output[idx][j] * v }
    return value, h
}

func (n *adaptiveNeural) rank(host string, candidates []string, usage map[string]int) (string, bool) {
    quic := strings.HasPrefix(host, "udp:")
    n.mu.Lock()
    defer n.mu.Unlock()
    if n.weights == nil { return "", false }
    best := ""
    bestScore := math.Inf(-1)
    for _, tag := range candidates {
        idx := nnCandidateIndex(tag, quic)
        if idx < 0 { continue }
        score, _ := nnForward(n.weights, host, idx, quic)
        // A bounded usage penalty forces exploration on new destinations;
        // the downloaded seed never locks a site to one strategy.
        score -= math.Min(float64(usage[tag]), 20) * 0.14
        if score > bestScore { best, bestScore = tag, score }
    }
    return best, best != ""
}

func nnClamp(x float64) float64 { return math.Max(-4, math.Min(4, x)) }

func (n *adaptiveNeural) learn(host, candidate string, downstream int64) {
    // These are weak *transport* rewards only. Short app/API payloads
    // are inconclusive; never read or classify encrypted application data.
    if downstream > 0 && downstream < adaptiveSmallResponseThreshold { return }
    quic := strings.HasPrefix(host, "udp:")
    idx := nnCandidateIndex(candidate, quic)
    if idx < 0 { return }
    reward := 0.0
    if downstream >= adaptivePayloadThreshold { reward = 1 }
    if downstream >= adaptiveSmallResponseThreshold && downstream < adaptivePayloadThreshold { reward = 0.7 }
    n.mu.Lock()
    defer n.mu.Unlock()
    if n.weights == nil { return }
    w := n.weights
    logit, hidden := nnForward(w, host, idx, quic)
    prob := 1 / (1 + math.Exp(-math.Max(-12, math.Min(12, logit))))
    delta := (reward - prob) * 0.03 // small, clamped SGD update
    var oldOutput [adaptiveNNHidden]float64
    copy(oldOutput[:], w.Output[idx])
    for i, v := range hidden {
        w.Output[idx][i] = nnClamp(w.Output[idx][i] + delta*v)
    }
    w.OutputBias[idx] = nnClamp(w.OutputBias[idx] + delta)
    inputs := nnFeatures(host, quic)
    for i, v := range hidden {
        if v <= 0 { continue } // ReLU derivative
        gradient := delta * oldOutput[i] * 0.1
        w.Bias[i] = nnClamp(w.Bias[i] + gradient)
        for j, x := range inputs {
            w.Hidden[i][j] = nnClamp(w.Hidden[i][j] + gradient*x)
        }
    }
}
