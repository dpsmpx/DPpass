//go:build linux

package bridge

import (
    "bytes"
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


func generatedSparseTestModel(t *testing.T, budget int64, deep int) []byte {
    t.Helper()
    first := 64
    w := adaptiveNNWeights{
        Format: "dppass-zapret2-mlp-v3",
        Parameters: budget,
        Seed: "0123456789abcdef",
        Hidden: make([][]float64, first),
        Bias: make([]float64, first),
        DeepHidden: make([][]float64, deep),
        DeepBias: make([]float64, deep),
        Output: make([][]float64, adaptiveNNOutput),
        OutputBias: make([]float64, adaptiveNNOutput),
        ContextBias: make([][]float64, adaptiveNNContexts),
        ContextObservations: make([]int, adaptiveNNContexts),
        Sparse: make(map[string]float64),
    }
    for i:=0;i<first;i++ { w.Hidden[i] = make([]float64, adaptiveNNInput); w.Hidden[i][0] = 0.02 }
    for i:=0;i<deep;i++ {
        w.DeepHidden[i] = make([]float64, first)
        w.DeepHidden[i][0] = 0.02
    }
    final := first
    if deep>0 { final = deep }
    for i:=0;i<adaptiveNNOutput;i++ { w.Output[i]=make([]float64,final) }
    for i:=0;i<adaptiveNNContexts;i++ { w.ContextBias[i]=make([]float64, adaptiveNNOutput) }
    if budget < nnDenseCount(&w) { t.Fatalf("budget too small %d", budget) }
    raw, err := json.Marshal(w)
    if err!=nil { t.Fatal(err) }
    return raw
}

func TestNeuralSparseHundredMillionParametersAndContextPersistence(t *testing.T) {
    defer func() {
        _=ConfigureZapret2NeuralModel(nil)
        _=ConfigureZapret2NeuralNetwork("UNKNOWN")
    }()
    raw:=generatedSparseTestModel(t, 100_000_000, 32)
    if len(raw) >= adaptiveNNMaxBytes { t.Fatal("dense allocation tracks logical budget") }
    if err:=ConfigureZapret2NeuralModel(raw);err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    for i:=0;i<6;i++ {
        zapret2Neural.learn("www.example.org","tlsrec-split",adaptivePayloadThreshold)
    }
    learned:=ExportZapret2NeuralModel()
    if len(learned)==0 {t.Fatal("learning not exported")}
    // Export must not clear dirty until a successful Android file write.
    if next:=ExportZapret2NeuralModel();!bytes.Equal(next,learned) {
        t.Fatal("unacknowledged snapshot was lost")
    }
    if err:=AcknowledgeZapret2NeuralModel(learned);err!=nil {t.Fatal(err)}
    if next:=ExportZapret2NeuralModel();len(next)!=0 {
        t.Fatal("acknowledged snapshot was exported again")
    }
    parsed,err:=parseAdaptiveNN(learned)
    if err!=nil {t.Fatal(err)}
    if parsed.Parameters!=100_000_000 || parsed.ContextObservations[0] != 6 {
        t.Fatalf("lost network context: %d %+v",parsed.Parameters,parsed.ContextObservations)
    }
    if len(parsed.Sparse)==0 {t.Fatal("large sparse slots never trained")}
    if err:=ConfigureZapret2NeuralNetwork("WIFI");err!=nil {t.Fatal(err)}
    for i:=0;i<3;i++ {zapret2Neural.learn("www.example.org","tlsrec-split",0)}
    learned=ExportZapret2NeuralModel()
    parsed,err=parseAdaptiveNN(learned)
    if err!=nil {t.Fatal(err)}
    if parsed.ContextObservations[0]!=6 || parsed.ContextObservations[3]!=3 {
        t.Fatalf("WIFI erased mobile learning: %+v",parsed.ContextObservations)
    }
    if err:=ConfigureZapret2NeuralModel(learned);err!=nil {t.Fatal(err)}
    zapret2Neural.mu.Lock()
    remembered:=zapret2Neural.weights.ContextObservations[0]
    zapret2Neural.mu.Unlock()
    if remembered!=6 {t.Fatal("snapshot did not survive reload")}
    if nnCandidateIndex("pass",false)!=-1 || nnCandidateIndex("pass",true)!=8 {
        t.Fatal("pass incorrectly indexes neural output")
    }
}

func TestNeuralSparseSchemaRejectsUnsafeBudgets(t *testing.T) {
    raw:=generatedSparseTestModel(t,100000,16)
    w,err:=parseAdaptiveNN(raw)
    if err!=nil {t.Fatal(err)}
    w.Parameters=nnDenseCount(w)-1
    bad,_:=json.Marshal(w)
    if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("too-small budget accepted")}
    w.Parameters=1_000_000_001
    bad,_=json.Marshal(w)
    if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("overflow budget accepted")}
    w.Parameters=100000
    w.Sparse=map[string]float64{"100000000": 0.2}
    bad,_=json.Marshal(w)
    if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("out-of-range slot accepted")}
}


func TestNeuralSnapshotAcknowledgementPreservesConcurrentNewLearning(t *testing.T) {
    defer func() {
        _=ConfigureZapret2NeuralModel(nil)
        _=ConfigureZapret2NeuralNetwork("UNKNOWN")
    }()
    if err:=ConfigureZapret2NeuralModel(generatedSparseTestModel(t,100_000_000,32));err!=nil {t.Fatal(err)}
    _=ConfigureZapret2NeuralNetwork("MOBILE")
    zapret2Neural.learn("www.example.org","tlsrec-split",adaptivePayloadThreshold)
    first:=ExportZapret2NeuralModel()
    if len(first)==0 {t.Fatal("first snapshot empty")}
    // A second flow arrives while Android is persisting first.
    zapret2Neural.learn("www.example.org","tlsrec-split",adaptivePayloadThreshold)
    if err:=AcknowledgeZapret2NeuralModel(first);err==nil {
        t.Fatal("stale acknowledgement cleared new observations")
    }
    next:=ExportZapret2NeuralModel()
    if len(next)==0 || bytes.Equal(next,first) {t.Fatal("new outcome was lost")}
    if err:=AcknowledgeZapret2NeuralModel(next);err!=nil {t.Fatal(err)}
    if pending:=ExportZapret2NeuralModel();len(pending)!=0 {
        t.Fatal("acknowledged native model remained dirty")
    }
    if err:=AcknowledgeZapret2NeuralModel(nil);err==nil {t.Fatal("empty ACK accepted")}
}

func TestNeuralRejectsUnsupportedTransportWithoutMutatingModel(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    if err:=ConfigureZapret2NeuralModel(generatedSparseTestModel(t,100000,16));err!=nil {t.Fatal(err)}
    for _,tc:=range []struct{host,method string}{
        {"http:example.test","tlsrec-split"},
        {"udp:example.test","split"},
        {"example.test","unknown"},
        {"example.test","pass"},
    } {
        if got,ok:=zapret2Neural.rank(tc.host,[]string{tc.method},nil);ok || got!="" {
            t.Fatalf("rank accepted incompatible method: %+v %s",tc,got)
        }
        zapret2Neural.learn(tc.host,tc.method,adaptivePayloadThreshold)
    }
    if len(ExportZapret2NeuralModel())!=0 {t.Fatal("incompatible method trained model")}
    if got,ok:=zapret2Neural.rank("http:example.test",[]string{"split"},nil);!ok || got!="split" {t.Fatal("valid legacy HTTP method lost",got)}
    zapret2Neural.learn("http:example.test","split",adaptivePayloadThreshold)
    if len(ExportZapret2NeuralModel())==0 {t.Fatal("compatible method failed to train")}
}

func TestNetworkConfigurationResetsGenerationButKeepsModelAndTargets(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    defer ConfigureZapret2NeuralNetwork("UNKNOWN")
    defer ConfigureZapret2AdaptiveHosts("")
    if err:=ConfigureZapret2AdaptiveHosts("example.test");err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralModel(generatedSparseTestModel(t,100000,16));err!=nil {t.Fatal(err)}
    zapret2Neural.learn("example.test","split",adaptivePayloadThreshold)
    before:=ExportZapret2NeuralModel()
    if len(before)==0 {t.Fatal("missing learned snapshot")}
    _,old:=zapret2Auto.chooseTracked("example.test")
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    if zapret2Auto.generationSnapshot()==old {t.Fatal("same category did not reset")}
    zapret2Auto.mu.Lock()
    _,targetKept:=zapret2Auto.selected["example.test"]
    count:=len(zapret2Auto.entries)
    zapret2Auto.mu.Unlock()
    if !targetKept || count!=0 {t.Fatal("wrong transient reset",targetKept,count)}
    zapret2Auto.observeTracked("example.test","split",adaptivePayloadThreshold,old)
    if !bytes.Equal(before,ExportZapret2NeuralModel()) {t.Fatal("old generation modified weights")}
    if err:=ConfigureZapret2NeuralNetwork("WIFI");err!=nil {t.Fatal(err)}
    if !bytes.Equal(before,ExportZapret2NeuralModel()) {t.Fatal("handoff modified saved weights")}
}
