//go:build linux

package main

import (
    "testing"
    "encoding/json"
    "net"
    "io"
    "strings"
    "time"
    "github.com/dpsmpx/dppass/tools/xray/zapret2"
)

func TestLineProtocol(t *testing.T) {
    hello := []byte{22,3,3,0,4,1,0,0,0}
    r := request(zapret2.Request{Tag:zapret2.TagPrefix+"split-1",Network:"tcp",First:hello})
    if r.Error != "" || r.Plan.Cut != 1 || !r.Plan.Applied {
        t.Fatalf("invalid Alpine plan: %+v",r)
    }
    huge := request(zapret2.Request{Tag:zapret2.TagPrefix+"fake-5",Network:"tcp",First:make([]byte,zapret2.MaxFirst+1)})
    if huge.Error == "" {t.Fatal("oversized payload accepted")}
}

func TestDirectPlannerCommandRejectsInvalidRequests(t *testing.T) {
    for _,req:=range []zapret2.Request{
        {Tag:"not-a-method",Network:"tcp"},
        {Tag:zapret2.TagPrefix+"auto",Network:"tcp"},
        {Tag:zapret2.TagPrefix+"pass",Network:"unknown"},
    } {
        r:=request(req)
        if r.Error=="" || r.Plan.Applied || r.Plan.Strategy!="" {t.Fatal("invalid request returned plan")}
    }
}

func TestAndroidReadinessWireContract(t *testing.T) {
    const input = "{\"tag\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"first\":\"FgMBAAQBAAAA\"}\n"
    const expected = "{\"plan\":{\"strategy\":\"dppass:exp-split-1\",\"network\":\"tcp\",\"applied\":true,\"cut\":1}}\n"
    req,err:=zapret2.ReadRequest(strings.NewReader(input))
    if err!=nil {t.Fatal(err)}
    out,err:=json.Marshal(request(req))
    if err!=nil || string(out)+"\n"!=expected {t.Fatalf("readiness wire changed: %s %v",out,err)}
    a,b:=net.Pipe()
    defer a.Close()
    defer b.Close()
    done:=make(chan struct{})
    go func(){defer close(done);defer b.Close();handleConnection(b)}()
    _=a.SetDeadline(time.Now().Add(time.Second))
    if _,err:=io.WriteString(a,input);err!=nil {t.Fatal(err)}
    got,err:=io.ReadAll(a)
    if err!=nil || string(got)!=expected {t.Fatalf("readiness IPC changed: %s %v",got,err)}
    <-done
}
