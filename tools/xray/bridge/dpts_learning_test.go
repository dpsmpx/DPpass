//go:build linux

package bridge

import "testing"

func TestDPTSNeuralRejectsNonVerifiedOrForeignSamples(t *testing.T) {
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    for _,tc:=range []struct{network,methods string}{
        {"MOBILE",""},
        {"MOBILE","plain"},
        {"MOBILE","fake-5,plain"},
        {"MOBILE","fake-5,fake-5"},
        {"MOBILE","root"},
        {"MOBILE","pass"},
        {"MOBILE","split-2"},
        {"MOBILE","fake-2"},
        {"MOBILE","fake-5,disorder,tlsrec-split,split,split-1,fake-3,unknown"},
        {"WIFI","fake-5"},
        {"OTHER","fake-5"},
    } {
        if err:=TrainZapret2NeuralFromDPTS(tc.network,tc.methods);err==nil {
            t.Fatalf("invalid training admission for %q/%q",tc.network,tc.methods)
        }
    }
}


func TestDPTSVerifiedHTMLDoesNotTrainPassiveTransportHead(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralModel(generatedSparseTestModel(t,100000,16));err!=nil {t.Fatal(err)}
    old:=zapret2Neural.weights.ContextBias[0][5]
    if err:=TrainZapret2NeuralFromDPTS("MOBILE","tlsrec-split");err!=nil {t.Fatal(err)}
    snapshot:=ExportZapret2NeuralModel()
    w,err:=parseAdaptiveNN(snapshot)
    if err!=nil {t.Fatal(err)}
    if w.ContextBias[0][5]!=old || w.ContextObservations[0]!=0 {t.Fatal("passive head was changed")}
    if w.VerifiedHTMLBias[0][5]<=0 || w.VerifiedHTMLObservations[0]!=1 {t.Fatal("missing HTML calibration")}
    if w.VerifiedHTMLObservations[1]!=0 || w.VerifiedHTMLObservations[2]!=0 {t.Fatal("cross-network training")}
}

func TestDPTSNetworkChangeRejectsStaleTrainingWithoutDirtyingModel(t *testing.T) {
    defer ConfigureZapret2NeuralModel(nil)
    defer ConfigureZapret2NeuralNetwork("UNKNOWN")
    if err:=ConfigureZapret2NeuralModel(generatedSparseTestModel(t,100000,16));err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralNetwork("MOBILE");err!=nil {t.Fatal(err)}
    if err:=ConfigureZapret2NeuralNetwork("WIFI");err!=nil {t.Fatal(err)}
    if err:=TrainZapret2NeuralFromDPTS("MOBILE","tlsrec-split");err==nil {t.Fatal("stale context admitted")}
    if len(ExportZapret2NeuralModel())!=0 {t.Fatal("stale context dirtied model")}
    if err:=TrainZapret2NeuralFromDPTS("WIFI","tlsrec-split");err!=nil {t.Fatal(err)}
    w,err:=parseAdaptiveNN(ExportZapret2NeuralModel())
    if err!=nil {t.Fatal(err)}
    if w.VerifiedHTMLObservations[0]!=0 || w.VerifiedHTMLObservations[1]!=1 || w.VerifiedHTMLObservations[2]!=0 {
        t.Fatal("wrong calibration context",w.VerifiedHTMLObservations)
    }
}
