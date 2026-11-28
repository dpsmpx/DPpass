//go:build linux

package bridge

// Local-only MLP plus sparse, lazily allocated trainable capacity.
// A 100-million-parameter budget is addressable but never materializes
// 100 million floats in RAM. Contextual heads learn separately per
// mobile/Wi-Fi/other and TLS/HTTP/QUIC. No destinations are persisted.
import (
    "github.com/dpsmpx/dppass/tools/xray/localdpi"
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
)

const (
    adaptiveNNInput = 8
    adaptiveNNMinHidden = 8
    adaptiveNNMaxHidden = 1024
    adaptiveNNContexts = 9
    adaptiveNNMaxDeep = 512
    adaptiveNNMaxParameters int64 = 1_000_000_000
    adaptiveNNMaxSparse = 4096
    adaptiveNNMaxBytes = 1 << 20
)

var adaptiveNNOutput = localdpi.ModelOutputCount()
var adaptiveNNHeadWidth = adaptiveNNOutput*(adaptiveNNInput+1)

type adaptiveNNWeights struct {
    Format string `json:"format"`
    Parameters int64 `json:"parameters,omitempty"`
    Seed string `json:"seed,omitempty"`
    Hidden [][]float64 `json:"hidden"`
    Bias []float64 `json:"bias"`
    DeepHidden [][]float64 `json:"deep_hidden"`
    DeepBias []float64 `json:"deep_bias"`
    Output [][]float64 `json:"output"`
    OutputBias []float64 `json:"output_bias"`
    ContextBias [][]float64 `json:"context_bias,omitempty"`
    ContextObservations []int `json:"context_observations,omitempty"`
    // Optional fixed-size verified HTML calibration, separate from the
    // historically mixed passive transport MLP and its sparse parameter budget.
    VerifiedHTMLBias [][]float64 `json:"verified_html_bias,omitempty"`
    VerifiedHTMLObservations []int `json:"verified_html_observations,omitempty"`
    Sparse map[string]float64 `json:"sparse"`
    Observations int `json:"observations,omitempty"`
}

type adaptiveNeural struct {
    mu sync.Mutex
    weights *adaptiveNNWeights
    dirty bool
    network int32 // coarse category, guarded by mu
}

func ConfigureZapret2NeuralNetwork(kind string) error {
    return zapret2Auto.configureNetwork(kind)
}

func (a *adaptiveSelector) configureNetwork(kind string) error {
    var category int32
    switch kind {
    case "MOBILE": category=1
    case "WIFI": category=2
    case "OTHER", "UNKNOWN": category=0
    default: return errors.New("invalid underlying network class")
    }
    // A network configuration is a session boundary even if its coarse
    // category is unchanged. Use the selector -> model lock order so a
    // new selection cannot inherit the previous network's generation or
    // contextual head. Keep configured targets and persistent weights.
    a.mu.Lock()
    defer a.mu.Unlock()
    a.neural.mu.Lock()
    defer a.neural.mu.Unlock()
    a.resetLocked()
    a.neural.network = category
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
        int64(adaptiveNNOutput)*(int64(last)+1) + int64(adaptiveNNContexts*adaptiveNNHeadWidth)
}

var adaptiveNNFormat = localdpi.ModelFormat()

func parseAdaptiveNN(raw []byte) (*adaptiveNNWeights, error) {
    if len(raw) == 0 || len(raw) > adaptiveNNMaxBytes {
        return nil, errors.New("invalid neural model length")
    }
    if err := checkModelJSON(raw); err != nil { return nil, err }
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
    if w.Format != adaptiveNNFormat ||
        count < adaptiveNNMinHidden || count > adaptiveNNMaxHidden ||
        len(w.Bias) != count || len(w.Output) != adaptiveNNOutput ||
        len(w.OutputBias) != adaptiveNNOutput {
        return nil, errors.New("unsupported neural model dimensions")
    }
    deep := len(w.DeepHidden)
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
        if len(row) != adaptiveNNHeadWidth || w.ContextObservations[i] < 0 ||
            w.ContextObservations[i] > 1_000_000_000 {
            return nil, errors.New("invalid contextual head dimensions")
        }
        for _, n := range row {
            if !validNNNumber(n) { return nil, errors.New("invalid contextual weight") }
        }
    }
    if len(w.VerifiedHTMLBias) != 0 || len(w.VerifiedHTMLObservations) != 0 {
        if len(w.VerifiedHTMLBias) != 3 || len(w.VerifiedHTMLObservations) != 3 {
            return nil, errors.New("invalid HTML calibration dimensions")
        }
        for i, row := range w.VerifiedHTMLBias {
            if len(row) != localdpi.TCPOutputCount() || w.VerifiedHTMLObservations[i] < 0 || w.VerifiedHTMLObservations[i] > 1_000_000_000 {
                return nil, errors.New("invalid HTML calibration")
            }
            for _, n := range row { if !validNNNumber(n) { return nil, errors.New("invalid HTML weight") } }
        }
    }
    if w.Parameters < nnDenseCount(&w) || w.Parameters > adaptiveNNMaxParameters ||
        len(w.Sparse) > adaptiveNNMaxSparse {
        return nil, errors.New("invalid parameter budget")
    }
    // Normalize an empty sparse map before learning.
    // Normalize it before installing the model: a nil map cannot be
    // written by the existing model update path.
    if w.Sparse==nil {w.Sparse=make(map[string]float64)}
    capacity := w.Parameters - nnDenseCount(&w)
    var sparseCounts [adaptiveNNContexts]int64
    for key, n := range w.Sparse {
        i, err := strconv.ParseInt(key, 10, 64)
        if err != nil || i < 0 || i >= capacity || strconv.FormatInt(i, 10) != key ||
            !validNNNumber(n) { return nil, errors.New("invalid sparse slot") }
        context:=int(i%adaptiveNNContexts)
        sparseCounts[context]++
        if sparseCounts[context]>nnContextSlots(context,min(capacity,int64(adaptiveNNMaxSparse))) {
            return nil,errors.New("sparse context quota exceeded")
        }
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

// Configure only the current model schema.
func ConfigureZapret2NeuralModel(raw []byte) error {
    return zapret2Auto.configureModel(raw)
}

func (a *adaptiveSelector) configureModel(raw []byte) error {
    var weights *adaptiveNNWeights
    if len(raw) != 0 {
        var err error
        weights, err = parseAdaptiveNN(raw)
        if err != nil {
            return err
        }
    }
    a.mu.Lock()
    defer a.mu.Unlock()
    a.neural.mu.Lock()
    defer a.neural.mu.Unlock()
    // A late result from a replaced model may not train the new model.
    a.resetLocked()
    a.neural.weights = weights
    a.neural.dirty = false
    return nil
}

// Export only changed weights. Android commits the bounded JSON atomically.
// Never export hostnames or subscription IDs. A network change changes the
// active context; it must NOT reload the original random seed over training.
func ExportZapret2NeuralModel() []byte {
    return zapret2Auto.neural.export()
}

func (n *adaptiveNeural) export() []byte {
    n.mu.Lock()
    defer n.mu.Unlock()
    if n.weights == nil || !n.dirty { return nil }
    raw, err := json.Marshal(n.weights)
    if err != nil || len(raw) > adaptiveNNMaxBytes { return nil }
    // Export is non-destructive: only acknowledge after Android has
    // durably written the snapshot. Otherwise failed disk I/O or a
    // regenerated user model silently discards the last update.
    return raw
}

// Acknowledge exactly the weights Android committed. If a connection
// learned more between export and acknowledgement, preserve its dirty bit
// for the next flush. Compare the exact serialized bytes rather than revision counters.
func AcknowledgeZapret2NeuralModel(saved []byte) error {
    return zapret2Auto.neural.acknowledge(saved)
}

func (n *adaptiveNeural) acknowledge(saved []byte) error {
    if len(saved) == 0 || len(saved) > adaptiveNNMaxBytes {
        return errors.New("invalid neural acknowledgement")
    }
    n.mu.Lock()
    defer n.mu.Unlock()
    if n.weights == nil { return errors.New("neural model not installed") }
    // Even a clean model can have been replaced since the export.
    // An acknowledgement must match the current bytes in either state.
    current, err := json.Marshal(n.weights)
    if err != nil || !bytes.Equal(current, saved) {
        return errors.New("neural model updated after snapshot")
    }
    n.dirty = false
    return nil
}

func nnCandidateIndex(tag string, quic bool) int {
    transport := localdpi.TLS
    if quic { transport = localdpi.QUIC }
    return localdpi.NeuralIndex(tag, transport)
}

// TCP output positions are shared across TLS/HTTP, but capability sets differ.
func nnHostTransport(host string) localdpi.Transport {
    if strings.HasPrefix(host,"udp:") {return localdpi.QUIC}
    if strings.HasPrefix(host,"http:") {return localdpi.HTTP}
    return localdpi.TLS
}

func nnFeatures(host string, quic bool, network int32) [adaptiveNNInput]float64 {
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
    switch network {
    case 1: f[6] = 1
    case 2: f[7] = 1
    }
    return f
}

func nnContext(host string, quic bool, category int32) int {
    protocol := 0
    if quic { protocol = 2 } else if strings.HasPrefix(host, "http:") { protocol = 1 }
    network := 2
    switch category {
    case 1: network = 0
    case 2: network = 1
    }
    return network*3 + protocol
}

func nnSparseKeys(w *adaptiveNNWeights, host string, idx int, quic bool, network int32) []string {
    capacity := w.Parameters - nnDenseCount(w)
    if capacity <= 0 { return nil }
    context := nnContext(host, quic, network)
    // Disjoint logical sparse slots: no cross-context hash collision,
    // even for budgets smaller than nine.
    slots:=nnContextSlots(context,capacity)
    if slots<=0 {return nil}
    features := nnFeatures(host, quic, network)
    keys := make([]string, 0, adaptiveNNInput)
    seen:=make(map[string]bool,adaptiveNNInput)
    for i, x := range features {
        if x <= 0 { continue }
        bucket := int(math.Min(15, math.Max(0, math.Floor(x*15))))
        // Hashing avoids plaintext destination persistence. The seed and
        // these sparse keys are private to this on-device generated model.
        message := fmt.Sprintf("%s|%d|%s|%d|%d|%d", w.Seed, context, host, idx, i, bucket)
        sum := sha256.Sum256([]byte(message))
        var v uint64
        for k:=0;k<7;k++ { v = v<<8 | uint64(sum[k]) }
        key:=strconv.FormatUint(v%uint64(slots)*adaptiveNNContexts+uint64(context),10)
        if !seen[key] {keys=append(keys,key);seen[key]=true}
    }
    return keys
}

func nnContextSlots(context int, capacity int64) int64 {
    if context<0 || context>=adaptiveNNContexts || capacity<=int64(context) {return 0}
    return 1+(capacity-1-int64(context))/adaptiveNNContexts
}

func nnForward(w *adaptiveNNWeights, host string, idx int, quic bool, network int32) (float64, []float64) {
    f := nnFeatures(host, quic, network)
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
    context := nnContext(host, quic, network)
    start:=idx*(adaptiveNNInput+1)
    head:=w.ContextBias[context]
    value += head[start]
    for i,v:=range f {value += head[start+1+i]*v}
    for _, key := range nnSparseKeys(w, host, idx, quic, network) {
        value += w.Sparse[key] * 0.5
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
        idx := localdpi.NeuralIndex(tag,nnHostTransport(host))
        if idx < 0 { continue }
        score, _ := nnForward(n.weights, host, idx, quic, n.network)
        // This signal proves only a bounded HTML GET for this exact service.
        // It cannot bias unrelated sites, QUIC, plain HTTP or API responses.
        if host == "www.youtube.com" && !quic && idx < localdpi.TCPOutputCount() && len(n.weights.VerifiedHTMLBias) == 3 {
            score += n.weights.VerifiedHTMLBias[nnContext(host,false,n.network)/3][idx]
        }
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
    idx := localdpi.NeuralIndex(candidate,nnHostTransport(host))
    if idx < 0 { return }
    reward := 0.0
    if downstream >= adaptivePayloadThreshold { reward = 1 }
    if downstream >= adaptiveSmallResponseThreshold && downstream < adaptivePayloadThreshold { reward = 0.7 }
    n.mu.Lock()
    defer n.mu.Unlock()
    if n.weights == nil { return }
    w := n.weights
    logit, _ := nnForward(w, host, idx, quic, n.network)
    prob := 1 / (1 + math.Exp(-math.Max(-12, math.Min(12, logit))))
    delta := (reward - prob) * 0.03
    // Keep the shared random feature extractor and prior frozen. Each
    // context trains its own method-specific affine head.
    context := nnContext(host, quic, n.network)
    start:=idx*(adaptiveNNInput+1)
    head:=w.ContextBias[context]
    head[start]=nnClamp(head[start]+delta)
    for i,v:=range nnFeatures(host,quic,n.network) {
        head[start+1+i]=nnClamp(head[start+1+i]+delta*v)
    }
    if w.ContextObservations[context] < 1_000_000_000 {
        w.ContextObservations[context]++
    }
    if w.Observations < 1_000_000_000 { w.Observations++ }
    nnLearnSparse(w,context,nnSparseKeys(w,host,idx,quic,n.network),delta*0.2)
    n.dirty = true
}

func hasSparseKey(m map[string]float64, key string) bool { _, ok := m[key]; return ok }

// Retain currently used features before admitting new keys. At a full
// quota evict the weakest inactive weight in this context only, breaking
// ties by numeric index. No additional persisted metadata or global quota.
func nnLearnSparse(w *adaptiveNNWeights,context int,keys []string,delta float64) {
    capacity:=w.Parameters-nnDenseCount(w)
    quota:=nnContextSlots(context,min(capacity,int64(adaptiveNNMaxSparse)))
    if quota==0 || len(keys)==0 {return}
    active:=make(map[string]bool,len(keys))
    novel:=make([]string,0,len(keys))
    for _,key:=range keys {
        slot,err:=strconv.ParseInt(key,10,64)
        if err!=nil || slot<0 || slot>=capacity || slot%adaptiveNNContexts!=int64(context) || strconv.FormatInt(slot,10)!=key || active[key] {continue}
        active[key]=true
        if previous,known:=w.Sparse[key];known {
            w.Sparse[key]=nnClamp(previous+delta)
        } else {novel=append(novel,key)}
    }
    if len(novel)==0 {return}
    count:=int64(0)
    for key:=range w.Sparse {
        slot,_:=strconv.ParseInt(key,10,64)
        if slot%adaptiveNNContexts==int64(context) {count++}
    }
    for _,key:=range novel {
        if count>=quota {
            victim:=""
            lowest:=math.Inf(1)
            var lowestSlot int64
            for old,value:=range w.Sparse {
                if active[old] {continue}
                slot,_:=strconv.ParseInt(old,10,64)
                if slot%adaptiveNNContexts!=int64(context) {continue}
                strength:=math.Abs(value)
                if strength<lowest || strength==lowest && slot<lowestSlot {
                    victim,lowest,lowestSlot=old,strength,slot
                }
            }
            // The current observation may contain more distinct active
            // keys than the quota; never evict one of them to admit another.
            if victim=="" {continue}
            delete(w.Sparse,victim)
            count--
        }
        w.Sparse[key]=nnClamp(delta)
        count++
    }
}
