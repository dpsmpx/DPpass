package localdpi

import (
    "reflect"
    "testing"
)

func TestCandidateOrder(t *testing.T) {
    for _, tc := range []struct{ transport Transport; want []string }{
        {TLS, []string{"split-1","split","fake-3","fake-5","disorder","tlsrec-split","pass"}},
        {HTTP, []string{"split","fake-3","fake-5","disorder","pass"}},
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
        NeuralIndex("split",QUIC)!=-1 || NeuralIndex("split-1",HTTP)!=-1 || NeuralIndex("unknown",TLS)!=-1 {
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

func TestNeuralLookupMatchesOrderedModelWithoutAllocations(t *testing.T) {
    for _, transport := range []Transport{TLS, HTTP, QUIC, 0, 255} {
        group, offset := TLS, 0
        if transport == QUIC { group, offset = QUIC, TCPOutputCount() }
        layout := ModelMethods(group)
        for _, m := range methods {
            want := -1
            for index, id := range layout {
                if id == m.id && m.transports & mask(transport) != 0 {
                    want = offset + index
                }
            }
            if got := NeuralIndex(m.id, transport); got != want {
                t.Fatalf("transport %d, method %s: got %d want %d", transport, m.id, got, want)
            }
        }
    }
    sum := 0
    allocs := testing.AllocsPerRun(1000, func() {
        sum += NeuralIndex("fake-5", TLS)
        sum += NeuralIndex("fake-5", HTTP)
        sum += NeuralIndex("pass", QUIC)
        sum += NeuralIndex("unknown", TLS)
        sum += TCPOutputCount() + ModelOutputCount()
    })
    if allocs != 0 || sum == 0 {
        t.Fatalf("unexpected lookup allocations: %v (sum %d)", allocs, sum)
    }
}

func TestCatalogAdmissionAndUnchangedModelPositions(t *testing.T) {
    for _,transport:=range []Transport{TLS,HTTP,QUIC,0,255} {
        expected:=map[string]bool{}
        for _,id:=range Candidates(transport) {expected[id]=true}
        for _,m:=range methods {
            if SupportsMethod(transport,m.id)!=expected[m.id] {
                t.Fatal("catalog admission disagrees with enumeration",transport,m.id)
            }
        }
        if SupportsMethod(transport,"unknown") || SupportsMethod(transport,"plain") {
            t.Fatal("unregistered wire name admitted")
        }
    }
    if SupportsMethod(HTTP,"split-1") || SupportsMethod(HTTP,"tlsrec-split") ||
        !SupportsMethod(TLS,"split-1") || NeuralIndex("split-1",TLS)!=0 ||
        NeuralIndex("tlsrec-split",TLS)!=5 || NeuralIndex("pass",QUIC)!=8 ||
        ModelFormat()!="dppass-strategy-mlp-v5:tcp=split-1,split,fake-3,fake-5,disorder,tlsrec-split;quic=fake-3,fake-5,pass" {
        t.Fatal("protocol admission or ordered model layout changed")
    }
}
