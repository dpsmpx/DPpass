//go:build linux

package main

import (
    "testing"
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
