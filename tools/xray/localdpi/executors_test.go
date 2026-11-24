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
