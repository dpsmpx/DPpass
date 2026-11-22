//go:build linux

package bridge

// Local-only MLP plus sparse, lazily allocated trainable capacity.
// A 100-million-parameter budget is addressable but never materializes
// 100 million floats in RAM. Contextual heads learn separately per
// mobile/Wi-Fi/other and TLS/HTTP/QUIC. No destinations are persisted.
import (
    "bytes"
    "crypto/sha256"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "math"
    "net"
    "strconv"
    "strings"
    "sync"
    "sync/atomic"
)

const (
    adaptiveNNInput = 8
    adaptiveNNMinHidden = 8
    adaptiveNNMaxHidden = 1024
    adaptiveNNOutput = 9 // 6 TCP + 3 QUIC; TCP pass rotates without neural weights
    adaptiveNNContexts = 9
    adaptiveNNMaxDeep = 512
    adaptiveNNMaxParameters int64 = 1_000_000_000
    adaptiveNNMaxSparse = 4096
    adaptiveNNMaxBytes = 1 << 20
)

type adaptiveNNWeights struct {
    Format string `json:"format"`
    Parameters int64 `json:"parameters,omitempty"`
    Seed string `json:"seed,omitempty"`
    Hidden [][]float64 `json:"hidden"`
    Bias []float64 `json:"bias"`
    DeepHidden [][]float64 `json:"deep_hidden,omitempty"`
    DeepBias []float64 `json:"deep_bias,omitempty"`
    Output [][]float64 `json:"output"`
    OutputBias []float64 `json:"output_bias"`
    ContextBias [][]float64 `json:"context_bias,omitempty"`
    ContextObservations []int `json:"context_observations,omitempty"`
    Sparse map[string]float64 `json:"sparse,omitempty"`
    Observations int `json:"observations,omitempty"`
}

type adaptiveNeural struct {
    mu sync.Mutex
    weights *adaptiveNNWeights
    dirty bool
}
var zapret2Neural adaptiveNeural

// Only network category, no carrier, SSID, geographic position or IP.
var zapret2NeuralNetwork atomic.Int32

func ConfigureZapret2NeuralNetwork(kind string) error {
    switch kind {
    case "MOBILE": zapret2NeuralNetwork.Store(1)
    case "WIFI": zapret2NeuralNetwork.Store(2)
    case "OTHER", "UNKNOWN": zapret2NeuralNetwork.Store(0)
    default: return errors.New("invalid underlying network class")
    }
    return nil
}

func validNNNumber(x float64) bool {
    return !math.IsNaN(x) && !math.IsInf(x, 0) && math.Abs(x) <= 4
}

func nnDenseCount(w *adaptiveNNWeights) int64 {
    first, deep := len(w.Hidden), len(w.DeepHidden)
    last := first
    if deep > 0 { last = deep }
    return int64(first)*(adaptiveNNInput+1) + int64(deep)*(int64(first)+1) +
        adaptiveNNOutput*(int64(last)+1) + adaptiveNNContexts*adaptiveNNOutput
}

func nnModern(w *adaptiveNNWeights) bool { return w.Format == "dppass-zapret2-mlp-v3" }

func parseAdaptiveNN(raw []byte) (*adaptiveNNWeights, error) {
    if len(raw) == 0 || len(raw) > adaptiveNNMaxBytes {
        return nil, errors.New("invalid neural model length")
    }
    var w adaptiveNNWeights
    decoder := json.NewDecoder(bytes.NewReader(raw))
    decoder.DisallowUnknownFields()
    if err := decoder.Decode(&w); err != nil {
        return nil, errors.New("invalid neural model JSON")
    }
    var extra json.RawMessage
    if err := decoder.Decode(&extra); err != io.EOF {
        return nil, errors.New("trailing neural model content")
    }
    count := len(w.Hidden)
    if w.Format != "dppass-zapret2-mlp-v2" && !nnModern(&w) ||
        count < adaptiveNNMinHidden || count > adaptiveNNMaxHidden ||
        len(w.Bias) != count || len(w.Output) != adaptiveNNOutput ||
        len(w.OutputBias) != adaptiveNNOutput {
        return nil, errors.New("unsupported neural model dimensions")
    }
    deep := len(w.DeepHidden)
    if nnModern(&w) {
        if deep > adaptiveNNMaxDeep || len(w.DeepBias) != deep {
            return nil, errors.New("invalid deeper hidden layer")
        }
        if len(w.Seed) != 16 { return nil, errors.New("bad sparse seed") }
        for _, c := range w.Seed {
            if c < '0' || c > '9' && (c < 'a' || c > 'f') {
                return nil, errors.New("bad sparse seed")
            }
        }
        if len(w.ContextBias) != adaptiveNNContexts ||
            len(w.ContextObservations) != adaptiveNNContexts ||
            w.Observations < 0 || w.Observations > 1_000_000_000 {
            return nil, errors.New("invalid contextual heads")
        }
        for i, row := range w.ContextBias {
            if len(row) != adaptiveNNOutput || w.ContextObservations[i] < 0 ||
                w.ContextObservations[i] > 1_000_000_000 {
                return nil, errors.New("invalid contextual head dimensions")
            }
            for _, n := range row {
                if !validNNNumber(n) { return nil, errors.New("invalid contextual weight") }
            }
        }
        if w.Parameters < nnDenseCount(&w) || w.Parameters > adaptiveNNMaxParameters ||
            len(w.Sparse) > adaptiveNNMaxSparse {
            return nil, errors.New("invalid parameter budget")
        }
        capacity := w.Parameters - nnDenseCount(&w)
        for key, n := range w.Sparse {
            i, err := strconv.ParseInt(key, 10, 64)
            if err != nil || i < 0 || i >= capacity || strconv.FormatInt(i, 10) != key ||
                !validNNNumber(n) { return nil, errors.New("invalid sparse slot") }
        }
    } else if deep > 0 || len(w.DeepBias) != 0 || len(w.ContextBias) != 0 ||
        w.Parameters != 0 || w.Seed != "" || len(w.Sparse) > 0 {
        return nil, errors.New("legacy model has modern parameters")
    }
    for i, row := range w.Hidden {
        if len(row) != adaptiveNNInput { return nil, errors.New("bad hidden matrix") }
        for _, n := range row {
            if !validNNNumber(n) { return nil, errors.New("bad hidden weight") }
        }
        if !validNNNumber(w.Bias[i]) { return nil, errors.New("bad hidden bias") }
    }
    for i, row := range w.DeepHidden {
        if len(row) != count || !validNNNumber(w.DeepBias[i]) {
            return nil, errors.New("bad deeper hidden matrix")
        }
        for _, n := range row {
            if !validNNNumber(n) { return nil, errors.New("bad deeper hidden weight") }
        }
    }
    last := count
    if deep > 0 { last = deep }
    for i, row := range w.Output {
        if len(row) != last { return nil, errors.New("bad output matrix") }
        for _, n := range row {
            if !validNNNumber(n) { return nil, errors.New("bad output weight") }
        }
        if !validNNNumber(w.OutputBias[i]) { return nil, errors.New("bad output bias") }
    }
    return &w, nil
}

// Existing JNI configuration API and legacy v2 weights remain supported.
func ConfigureZapret2NeuralModel(raw []byte) error {
    if len(raw) == 0 {
        zapret2Neural.mu.Lock()
        zapret2Neural.weights = nil
        zapret2Neural.dirty = false
        zapret2Neural.mu.Unlock()
        return nil
    }
    w, err := parseAdaptiveNN(raw)
    if err != nil { return err }
    zapret2Neural.mu.Lock()
    zapret2Neural.weights = w
    zapret2Neural.dirty = false
    zapret2Neural.mu.Unlock()
    return nil
}

// Export only changed weights. Android commits the bounded JSON atomically.
// Never export hostnames or subscription IDs. A network change changes the
// active context; it must NOT reload the original random seed over training.
func ExportZapret2NeuralModel() []byte {
    zapret2Neural.mu.Lock()
    defer zapret2Neural.mu.Unlock()
    if zapret2Neural.weights == nil || !zapret2Neural.dirty { return nil }
    raw, err := json.Marshal(zapret2Neural.weights)
    if err != nil || len(raw) > adaptiveNNMaxBytes { return nil }
    zapret2Neural.dirty = false
    return raw
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
    switch zapret2NeuralNetwork.Load() {
    case 1: f[6] = 1
    case 2: f[7] = 1
    }
    return f
}

func nnContext(host string, quic bool) int {
    protocol := 0
    if quic { protocol = 2 } else if strings.HasPrefix(host, "http:") { protocol = 1 }
    network := 2
    switch zapret2NeuralNetwork.Load() {
    case 1: network = 0
    case 2: network = 1
    }
    return network*3 + protocol
}

func nnSparseKeys(w *adaptiveNNWeights, host string, idx int, quic bool) []string {
    capacity := w.Parameters - nnDenseCount(w)
    if capacity <= 0 { return nil }
    context := nnContext(host, quic)
    features := nnFeatures(host, quic)
    keys := make([]string, 0, adaptiveNNInput)
    for i, x := range features {
        if x <= 0 { continue }
        bucket := int(math.Min(15, math.Max(0, math.Floor(x*15))))
        // Hashing avoids plaintext destination persistence. The seed and
        // these sparse keys are private to this on-device generated model.
        message := fmt.Sprintf("%s|%d|%s|%d|%d|%d", w.Seed, context, host, idx, i, bucket)
        sum := sha256.Sum256([]byte(message))
        var v uint64
        for k:=0;k<7;k++ { v = v<<8 | uint64(sum[k]) }
        keys = append(keys, strconv.FormatUint(v%uint64(capacity), 10))
    }
    return keys
}

func nnForward(w *adaptiveNNWeights, host string, idx int, quic bool) (float64, []float64) {
    f := nnFeatures(host, quic)
    h := make([]float64, len(w.Bias))
    for i := range h {
        sum := w.Bias[i]
        for j, v := range f { sum += w.Hidden[i][j] * v }
        h[i] = math.Max(0, sum)
    }
    if len(w.DeepHidden) > 0 {
        d := make([]float64, len(w.DeepHidden))
        for i := range d {
            sum := w.DeepBias[i]
            for j, v := range h { sum += w.DeepHidden[i][j] * v }
            d[i] = math.Max(0, sum)
        }
        h = d
    }
    value := w.OutputBias[idx]
    for j, v := range h { value += w.Output[idx][j] * v }
    if nnModern(w) {
        context := nnContext(host, quic)
        value += w.ContextBias[context][idx]
        for _, key := range nnSparseKeys(w, host, idx, quic) {
            value += w.Sparse[key] * 0.5
        }
    }
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
        // Explore uncertain candidates, not just a random neural prior.
        score -= math.Min(float64(usage[tag]), 20) * 0.14
        if score > bestScore { best, bestScore = tag, score }
    }
    return best, best != ""
}

func nnClamp(x float64) float64 { return math.Max(-4, math.Min(4, x)) }

func (n *adaptiveNeural) learn(host, candidate string, downstream int64) {
    // Do not treat an ACK, TLS handshake or short API metadata as proof
    // that video/content is usable.
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
    delta := (reward - prob) * 0.03
    oldOutput := append([]float64(nil), w.Output[idx]...)
    for i, v := range hidden {
        w.Output[idx][i] = nnClamp(w.Output[idx][i] + delta*v)
    }
    w.OutputBias[idx] = nnClamp(w.OutputBias[idx] + delta)
    if nnModern(w) {
        // Scenario-specific heads are adapted faster than shared features,
        // so MOBILE failures don't erase learned WIFI priorities.
        context := nnContext(host, quic)
        w.ContextBias[context][idx] = nnClamp(w.ContextBias[context][idx] + delta)
        if w.ContextObservations[context] < 1_000_000_000 {
            w.ContextObservations[context]++
        }
        if w.Observations < 1_000_000_000 { w.Observations++ }
        for _, key := range nnSparseKeys(w, host, idx, quic) {
            if len(w.Sparse) < adaptiveNNMaxSparse || hasSparseKey(w.Sparse, key) {
                w.Sparse[key] = nnClamp(w.Sparse[key] + delta * 0.2)
            }
        }
        // Only train the final layer and the contextual heads for deep
        // models: this protects shared feature extraction from forgetting.
    } else {
        inputs := nnFeatures(host, quic)
        for i, v := range hidden {
            if v <= 0 { continue }
            gradient := delta * oldOutput[i] * 0.1
            w.Bias[i] = nnClamp(w.Bias[i] + gradient)
            for j, x := range inputs {
                w.Hidden[i][j] = nnClamp(w.Hidden[i][j] + gradient*x)
            }
        }
    }
    n.dirty = true
}

func hasSparseKey(m map[string]float64, key string) bool { _, ok := m[key]; return ok }
