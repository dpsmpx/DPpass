//go:build linux

package bridge

import (
    "bytes"
    "testing"
)

func TestModelJSONRejectsAmbiguousFields(t *testing.T) {
    raw:=generatedSparseTestModel(t,100000,16)
    if _,err:=parseAdaptiveNN(raw);err!=nil {t.Fatal(err)}
    current:=generatedTestModel(t,32)
    if _,err:=parseAdaptiveNN(current);err!=nil {t.Fatal(err)}
    for _,tc:=range []struct{old,next string}{
        {`"format":`,`"format":"bad","format":`},
        {`"format":`,`"Format":`},
        {`"sparse":{}`,`"sparse":{"0":0.1,"0":0.2}`},
        {`"sparse":{}`,`"sparse":{"0":null}`},
        {`"bias":[0,`,`"bias":[null,`},
        {`"context_observations":[0,`,`"context_observations":[null,`},
        {`"sparse":{}`,`"sparse":{"0":[[[[[0]]]]]}`},
    } {
        bad:=bytes.Replace(raw,[]byte(tc.old),[]byte(tc.next),1)
        if bytes.Equal(bad,raw) {t.Fatal("fixture not mutated",tc.old)}
        if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("ambiguous fixture accepted",tc.old)}
    }
    for _,bad:=range [][]byte{append(bytes.Clone(raw),[]byte("{}")...), {0xff}} {
        if _,err:=parseAdaptiveNN(bad);err==nil {t.Fatal("bad JSON accepted")}
    }
}
