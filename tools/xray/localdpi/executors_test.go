package localdpi

import (
    "reflect"
    "testing"
)

func TestExecutorSetKeepsContextsSeparate(t *testing.T) {
    vpn,err:=NewCapabilities(VPNSocket,false,[]Support{{TLS,"pass"},{TLS,"split"}})
    if err!=nil {t.Fatal(err)}
    root,err:=NewCapabilities(RootPacket,true,[]Support{{TLS,"pass"}})
    if err!=nil {t.Fatal(err)}
    set,err:=NewExecutorSet(vpn,root)
    if err!=nil {t.Fatal(err)}
    if got:=set.Candidates(VPNSocket,TLS);!reflect.DeepEqual(got,[]string{"split","pass"}) {t.Fatal(got)}
    if got:=set.Candidates(RootPacket,TLS);!reflect.DeepEqual(got,[]string{"pass"}) {t.Fatal(got)}
    if len(set.Candidates(RootSocket,TLS))!=0 {t.Fatal("missing executor substituted")}
    flow:=FlowIdentity{Executor:VPNSocket,Generation:4,Transport:TLS,MethodID:"pass"}
    if !set.Admit(flow,VPNSocket,4) || set.Admit(flow,RootPacket,4) || set.Admit(flow,VPNSocket,5) {
        t.Fatal("executor or generation separation failed")
    }
    flow.Executor=RootPacket
    flow.MethodID="split"
    if set.Admit(flow,RootPacket,4) {t.Fatal("unregistered root method accepted")}
    if _,err:=NewExecutorSet(vpn,vpn);err==nil {t.Fatal("duplicate executor")}
    if _,err:=NewExecutorSet(Capabilities{});err==nil {t.Fatal("zero capability accepted")}
    var empty ExecutorSet
    if empty.Admit(flow,RootPacket,4) {t.Fatal("zero registry accepted")}
}

func TestReadEvidenceIsNeverCancellationOrContent(t *testing.T) {
    if got:=SocketDownstream(0);got.Kind!=Unknown {t.Fatal(got)}
    if got:=SocketDownstream(-1);got.Kind!=Unknown {t.Fatal(got)}
    if got:=SocketDownstream(1<<20);got.Kind!=Downstream || got.Bytes!=1<<20 {t.Fatal(got)}
}

func TestExecutorSetOwnsRegistrationSnapshot(t *testing.T) {
    if _,err:=NewExecutorSet();err==nil {t.Fatal("empty registry accepted")}
    caps,err:=NewCapabilities(VPNSocket,false,[]Support{{TLS,"pass"}})
    if err!=nil {t.Fatal(err)}
    set,err:=NewExecutorSet(caps)
    if err!=nil {t.Fatal(err)}
    delete(caps.supported,Support{TLS,"pass"})
    caps.supported[Support{QUIC,"pass"}]=struct{}{}
    if !reflect.DeepEqual(set.Candidates(VPNSocket,TLS),[]string{"pass"}) {
        t.Fatal("snapshot changed after original map mutation")
    }
    if len(set.Candidates(VPNSocket,QUIC))!=0 {t.Fatal("new capability leaked into snapshot")}
    out:=set.Candidates(VPNSocket,TLS)
    out[0]="unknown"
    if !reflect.DeepEqual(set.Candidates(VPNSocket,TLS),[]string{"pass"}) {
        t.Fatal("candidate slice mutation changed registry")
    }
    empty,err:=NewCapabilities(RootSocket,true,nil)
    if err!=nil {t.Fatal(err)}
    emptySet,err:=NewExecutorSet(empty)
    if err!=nil || len(emptySet.Candidates(RootSocket,TLS))!=0 {
        t.Fatal("registered executor without methods should remain unavailable",err)
    }
}

func TestExecutorRegistryRejectsInvalidCapabilitySnapshot(t *testing.T) {
    for _,entry:=range []Support{{HTTP,"split-1"},{QUIC,"split"},{Transport(255),"pass"},{TLS,"unknown"}} {
        c,err:=NewCapabilities(VPNSocket,false,[]Support{{TLS,"pass"}})
        if err!=nil {t.Fatal(err)}
        c.supported[entry]=struct{}{}
        if _,err:=NewExecutorSet(c);err==nil {
            t.Fatal("registry accepted incompatible capability",entry)
        }
    }
}
