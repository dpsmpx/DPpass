//go:build linux

package zapret2

import (
    "bytes"
    "encoding/binary"
    "testing"
)

func TestTLSRecordChainLocalPlan(t *testing.T) {
    input:=tlsClientHelloFixture(t,"example.com")
    tag:=TagPrefix+"tlsrec-chain"
    p,err:=BuildPlan(tag,"tcp",input)
    if err!=nil || !p.Applied || len(p.Rewrite)!=len(input)+10 {t.Fatal("chain plan",err)}
    if err:=validatePlan(tag,"tcp",input,p);err!=nil {t.Fatal(err)}
    var joined []byte
    for _,part:=range [][]byte{p.Rewrite[:p.Cut],p.Rewrite[p.Cut:p.Cut2],p.Rewrite[p.Cut2:]} {
        if len(part)<6 || !bytes.Equal(part[:3],input[:3]) || int(binary.BigEndian.Uint16(part[3:5]))!=len(part)-5 {
            t.Fatal("invalid record frame")
        }
        joined=append(joined,part[5:]...)
    }
    if !bytes.Equal(joined,input[5:]) {t.Fatal("handshake changed")}
    p.Rewrite=bytes.Clone(p.Rewrite)
    p.Rewrite[len(p.Rewrite)-1]^=1
    if validatePlan(tag,"tcp",input,p)==nil {t.Fatal("modified handshake admitted")}
    for _,bad:=range [][]byte{input[:len(input)-1],tlsClientHelloFixture(t,"example.org"),append(bytes.Clone(input),0)} {
        plan,err:=BuildPlan(tag,"tcp",bad)
        if err!=nil || plan.Applied {t.Fatal("nonfixture admitted",err)}
    }
}
