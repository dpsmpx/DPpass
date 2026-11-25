package localdpi

import (
    "reflect"
    "testing"
)

func TestCandidateOrder(t *testing.T) {
    for _, tc := range []struct{ transport Transport; want []string }{
        {TLS, []string{"split-1","split","fake-3","fake-5","disorder","tlsrec-split","pass"}},
        {HTTP, []string{"split-1","split","fake-3","fake-5","disorder","pass"}},
        {QUIC, []string{"fake-3","fake-5","pass"}},
        {0, []string{}},
    } {
        if got := Candidates(tc.transport); !reflect.DeepEqual(got, tc.want) {
            t.Fatalf("transport %d: got %v want %v",tc.transport,got,tc.want)
        }
    }
    want := []string{"fake-3","fake-5","disorder","split","split-1","tlsrec-split"}
    if got := Profiles(); !reflect.DeepEqual(got,want) { t.Fatalf("profiles %v",got) }
}

func TestModelOutputMapping(t *testing.T) {
    for _, transport := range []Transport{TLS, QUIC} {
        index := 0
        if transport == QUIC { index = TCPOutputCount() }
        for _, m := range methods {
            train := m.trainTCP
            if transport == QUIC { train = m.trainQUIC }
            if !train { continue }
            if got:=NeuralIndex(m.id,transport);got!=index { t.Fatalf("%s: %d != %d",m.id,got,index) }
            index++
        }
    }
    if NeuralIndex("pass",TLS)!=-1 || NeuralIndex("tlsrec-split",HTTP)!=-1 ||
        NeuralIndex("split",QUIC)!=-1 || NeuralIndex("unknown",TLS)!=-1 {
        t.Fatal("unsupported method has neural output")
    }
}

func TestCatalogUniqueAndImmutable(t *testing.T) {
    seen:=map[string]bool{}
    for _,m:=range methods {
        if m.id=="" || seen[m.id] { t.Fatalf("duplicate or empty id: %q",m.id) }
        seen[m.id]=true
    }
    first:=Candidates(TLS)
    first[0]="changed"
    if Candidates(TLS)[0]!="split-1" { t.Fatal("mutable shared catalog") }
}

func TestModelLayoutHasNoUnmappedOrDuplicateSlots(t *testing.T) {
    seen:=make(map[int]string)
    for _,transport:=range []Transport{TLS,QUIC} {
        for _,id:=range Candidates(transport) {
            idx:=NeuralIndex(id,transport)
            if idx<0 {continue}
            if idx>=ModelOutputCount() {t.Fatal("index outside model",id,idx)}
            if _,exists:=seen[idx];exists {t.Fatal("duplicate index",idx)}
            seen[idx]=id
        }
    }
    if len(seen)!=ModelOutputCount() {t.Fatal("incomplete model layout",seen)}
    for _,id:=range []string{"pass","plain","fake-2","split-2","unknown"} {
        if HTMLIndex(id)!=-1 {t.Fatal("invalid calibration slot",id)}
    }
    for _,id:=range Candidates(TLS) {
        if id!="pass" && HTMLIndex(id)!=NeuralIndex(id,TLS) {t.Fatal(id)}
    }
}
