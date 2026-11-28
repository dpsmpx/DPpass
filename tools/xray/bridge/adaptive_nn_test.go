//go:build linux

package bridge

import (
    "bytes"
    "encoding/json"
    "math"
    "strconv"
    "strings"
    "testing"
)

// Construct the same schema Android generates, without any downloadable
// seed or pretrained assets. A large local model must remain bounded.
func generatedTestModel(t *testing.T, hidden int) []byte {
    t.Helper()
    w := adaptiveNNWeights{
        Format: adaptiveNNFormat,
        Seed: "0123456789abcdef",
        DeepHidden: [][]float64{},
        DeepBias: []float64{},
        ContextBias: make([][]float64, adaptiveNNContexts),
        ContextObservations: make([]int, adaptiveNNContexts),
        Sparse: make(map[string]float64),
        Hidden: make([][]float64, hidden),
        Bias: make([]float64, hidden),
        Output: make([][]float64, adaptiveNNOutput),
        OutputBias: make([]float64, adaptiveNNOutput),
    }
    for i := range w.ContextBias { w.ContextBias[i] = make([]float64, adaptiveNNHeadWidth) }
    w.Parameters = nnDenseCount(&w)
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
    const host="www.youtube.com"
    inst,g:=newSiteSearchTestRun(t,host,[]string{"1.1.1.1","8.8.8.8"})
    for ip:=0;ip<2;ip++ {
        for attempt:=1;attempt<=3;attempt++ {
            recordSiteSearchTestSample(inst,host,g,ip,attempt,"h1","plain","timeout_tls",8000)
            recordSiteSearchTestSample(inst,host,g,ip,attempt,"h1","fake-5","ok",1100)
        }
    }
    if !commitSiteSearchTestRun(inst,host,"fake-5",g) {t.Fatal("verified site preference rejected")}
    if got := zapret2Auto.choose(host); got != "fake-5" {
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
        []byte(strings.Replace(string(raw), adaptiveNNFormat, "bad", 1)),
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
        Format: adaptiveNNFormat,
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
    for i:=0;i<adaptiveNNContexts;i++ { w.ContextBias[i]=make([]float64, adaptiveNNHeadWidth) }
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

func TestModernModelNormalizesAbsentSparseMap(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    raw:=generatedSparseTestModel(t,100000,16)
    for _,replacement:=range []string{"", ",\"sparse\":null"} {
        fixture:=bytes.Replace(raw,[]byte(",\"sparse\":{}"),[]byte(replacement),1)
        if bytes.Equal(raw,fixture) {t.Fatal("fixture missing sparse field")}
        w,err:=parseAdaptiveNN(fixture)
        if err!=nil || w.Sparse==nil || len(w.Sparse)!=0 {t.Fatal("empty sparse map not normalized",err)}
        canonical,err:=json.Marshal(w)
        if err!=nil || !bytes.Contains(canonical,[]byte("\"sparse\":{}")) {t.Fatal("invalid normalized serialization",err)}
        if err:=ConfigureZapret2NeuralModel(fixture);err!=nil {t.Fatal(err)}
        zapret2Neural.mu.Lock()
        zapret2Neural.weights.Sparse["0"]=0.125
        zapret2Neural.dirty=true
        zapret2Neural.mu.Unlock()
        exported:=ExportZapret2NeuralModel()
        persisted,err:=parseAdaptiveNN(exported)
        if err!=nil || persisted.Sparse["0"]!=0.125 {t.Fatal("sparse snapshot lost",err)}
    }
}

func TestNeuralAcknowledgementRejectsReplacedCleanModel(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    raw:=generatedSparseTestModel(t,100000,16)
    if err:=ConfigureZapret2NeuralModel(raw);err!=nil {t.Fatal(err)}
    zapret2Neural.mu.Lock()
    zapret2Neural.weights.Observations=1
    zapret2Neural.dirty=true
    zapret2Neural.mu.Unlock()
    old:=ExportZapret2NeuralModel()
    if len(old)==0 {t.Fatal("missing snapshot")}
    if err:=AcknowledgeZapret2NeuralModel(old);err!=nil {t.Fatal(err)}
    if err:=AcknowledgeZapret2NeuralModel(old);err!=nil {t.Fatal("matching acknowledgement not idempotent",err)}
    replacement,err:=parseAdaptiveNN(raw)
    if err!=nil {t.Fatal(err)}
    replacement.Seed="fedcba9876543210"
    next,err:=json.Marshal(replacement)
    if err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralModel(next);err!=nil {t.Fatal(err)}
    if err:=AcknowledgeZapret2NeuralModel(old);err==nil {t.Fatal("stale acknowledgement accepted for replacement")}
    if len(ExportZapret2NeuralModel())!=0 {t.Fatal("stale acknowledgement changed clean state")}
    if err:=AcknowledgeZapret2NeuralModel(next);err!=nil {t.Fatal("matching clean snapshot rejected",err)}
}

func TestRejectPreviousModelFormats(t *testing.T) {
    raw := generatedTestModel(t, 32)
    for _, previous := range []string{"dppass-zapret2-mlp-v2", "dppass-zapret2-mlp-v3",
        "dppass-strategy-mlp-v4", strings.Replace(adaptiveNNFormat, "split-1,split,", "split,split-1,", 1)} {
        if _,err := parseAdaptiveNN([]byte(strings.Replace(string(raw), adaptiveNNFormat, previous, 1))); err == nil { t.Fatal("previous format accepted", previous) }
    }
}

func TestModelRejectsInvalidObservationMetadata(t *testing.T) {
    raw:=generatedTestModel(t,32)
    w,err:=parseAdaptiveNN(raw)
    if err!=nil {t.Fatal(err)}
    w.Observations=42
    valid,err:=json.Marshal(w)
    if err!=nil {t.Fatal(err)}
    parsed,err:=parseAdaptiveNN(valid)
    if err!=nil || parsed.Observations!=42 {t.Fatal("valid count lost",err)}
    for _,change:=range []func(*adaptiveNNWeights){
        func(w *adaptiveNNWeights){w.Observations=-1},
        func(w *adaptiveNNWeights){w.Observations=1_000_000_001},
        func(w *adaptiveNNWeights){w.ContextObservations=[]int{1}},
    } {
        candidate,err:=parseAdaptiveNN(valid)
        if err!=nil {t.Fatal(err)}
        change(candidate)
        bad,err:=json.Marshal(candidate)
        if err!=nil {t.Fatal(err)}
        if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("invalid observation metadata accepted")}
    }
}

// Exercise all nine contexts. Updating one must not modify any other
// context's prediction even with a tiny, collision-prone sparse budget.
func TestStrategyV5IndependentContextHeads(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    defer ConfigureZapret2NeuralNetwork("UNKNOWN")
    w,err:=parseAdaptiveNN(generatedTestModel(t,32))
    if err!=nil {t.Fatal(err)}
    w.Parameters+=13
    raw,err:=json.Marshal(w)
    if err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralModel(raw);err!=nil {t.Fatal(err)}
    hosts:=[]string{"example.test","http:example.test","udp:example.test"}
    networks:=[]string{"MOBILE","WIFI","UNKNOWN"}
    scores:=func() []float64 {
        var out []float64
        for _,network:=range networks {
            if err:=ConfigureZapret2NeuralNetwork(network);err!=nil {t.Fatal(err)}
            for _,host:=range hosts {
                q:=strings.HasPrefix(host,"udp:")
                zapret2Neural.mu.Lock()
                score,_:=nnForward(zapret2Neural.weights,host,2,q)
                if q {score,_=nnForward(zapret2Neural.weights,host,6,q)}
                zapret2Neural.mu.Unlock()
                out=append(out,score)
            }
        }
        return out
    }
    before:=scores()
    for i,network:=range networks {
        for j,host:=range hosts {
            if err:=ConfigureZapret2NeuralNetwork(network);err!=nil {t.Fatal(err)}
            for k:=0;k<3;k++ {zapret2Neural.learn(host,"fake-3",adaptivePayloadThreshold)}
            after:=scores()
            index:=i*3+j
            for k:=range after {
                if k==index {if after[k]<=before[k] {t.Fatal("head did not learn",index)}} else if after[k]!=before[k] {t.Fatal("cross-context change",index,k)}
            }
            before=after
        }
    }
    learned:=ExportZapret2NeuralModel()
    parsed,err:=parseAdaptiveNN(learned)
    if err!=nil {t.Fatal(err)}
    if len(parsed.Sparse)>13 {t.Fatal("sparse budget exceeded")}
    for i,count:=range parsed.ContextObservations {if count!=3 {t.Fatal("missing head observations",i,count)}}
    if _,err:=parseAdaptiveNN(bytes.Replace(learned,[]byte("strategy-mlp-v5"),[]byte("strategy-mlp-v4"),1));err==nil {t.Fatal("old format accepted")}
}

// Full contexts remain trainable; neither an active weight nor an unrelated
// context may be evicted. Tie resolution is independent of map iteration.
func TestStrategySparseRenewalAtCapacity(t *testing.T) {
    w,err:=parseAdaptiveNN(generatedTestModel(t,32))
    if err!=nil {t.Fatal(err)}
    w.Parameters+=10000
    quota:=nnContextSlots(0,adaptiveNNMaxSparse)
    for i:=int64(0);i<quota;i++ {
        w.Sparse[strconv.FormatInt(i*adaptiveNNContexts,10)]=0.5
    }
    w.Sparse["0"]=0.01
    w.Sparse["9"]=-0.01
    w.Sparse["18"]=0.001
    w.Sparse["1"]=0.001
    novel:=strconv.FormatInt(quota*adaptiveNNContexts,10)
    nnLearnSparse(w,0,[]string{"18",novel,novel,"1"},0.1)
    if len(w.Sparse)!=int(quota)+1 || hasSparseKey(w.Sparse,"0") ||
        w.Sparse["9"]!=-0.01 || math.Abs(w.Sparse["18"]-0.101)>1e-12 || w.Sparse["1"]!=0.001 ||
        w.Sparse[novel]!=0.1 {t.Fatal("wrong context renewal")}
    raw,err:=json.Marshal(w)
    if err!=nil {t.Fatal(err)}
    if _,err:=parseAdaptiveNN(raw);err!=nil {t.Fatal("renewed snapshot invalid",err)}
}

func TestStrategySparseRenewalTinyQuota(t *testing.T) {
    w,err:=parseAdaptiveNN(generatedTestModel(t,32))
    if err!=nil {t.Fatal(err)}
    w.Parameters+=10
    w.Sparse["0"]=0.2
    w.Sparse["1"]=0.3
    nnLearnSparse(w,0,[]string{"0","9"},0.1)
    if len(w.Sparse)!=3 || w.Sparse["9"]!=0.1 {t.Fatal("tiny quota lost new feature")}
    nnLearnSparse(w,1,[]string{"1","10","-1"},0.1)
    if len(w.Sparse)!=3 || math.Abs(w.Sparse["1"]-0.4)>1e-12 {t.Fatal("context outside capacity changed")}
    nnLearnSparse(w,0,[]string{"0","9"},0.1)
    if len(w.Sparse)!=3 {t.Fatal("duplicate weight count")}
}
