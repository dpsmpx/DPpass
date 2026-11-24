package localdpi

import (
    "reflect"
    "testing"
)

func TestLegacyCandidateOrder(t *testing.T) {
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
    if got := LegacyProfiles(); !reflect.DeepEqual(got,want) { t.Fatalf("profiles %v",got) }
}

func TestModelOutputABI(t *testing.T) {
    ids := []string{"split-1","split","fake-3","fake-5","disorder","tlsrec-split"}
    for i,id := range ids {
        if got:=NeuralIndex(id,TLS);got!=i { t.Fatalf("TLS %s: %d",id,got) }
    }
    for i,id:=range []string{"fake-3","fake-5","pass"} {
        if got:=NeuralIndex(id,QUIC);got!=6+i { t.Fatalf("QUIC %s: %d",id,got) }
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
