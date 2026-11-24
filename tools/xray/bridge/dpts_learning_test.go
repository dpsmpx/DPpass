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
        {"MOBILE","fake-5,disorder,tlsrec-split,split,split-1,fake-3,unknown"},
        {"WIFI","fake-5"},
        {"OTHER","fake-5"},
    } {
        if err:=TrainZapret2NeuralFromDPTS(tc.network,tc.methods);err==nil {
            t.Fatalf("invalid training admission for %q/%q",tc.network,tc.methods)
        }
    }
}
