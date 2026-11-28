//go:build linux

package bridge

import (
	"testing"

	"github.com/dpsmpx/dppass/tools/xray/localdpi"
)

func TestAdaptiveExecutorOwnsFlowAndModel(t *testing.T) {
	rootCaps, err := localdpi.NewCapabilities(localdpi.RootSocket, true, []localdpi.Support{
		{Transport: localdpi.TLS, MethodID: "pass"},
		{Transport: localdpi.TLS, MethodID: "split"},
	})
	if err != nil {
		t.Fatal(err)
	}
	vpn := newAdaptiveSelector(socketCapabilities)
	otherVPN := newAdaptiveSelector(socketCapabilities)
	root := newAdaptiveSelector(rootCaps)
	model := generatedTestModel(t, 32)
	for _, setup := range []struct {
		selector *adaptiveSelector
		network  string
	}{{vpn, "WIFI"}, {otherVPN, "WIFI"}, {root, "MOBILE"}} {
		if err := setup.selector.configureModel(model); err != nil {
			t.Fatal(err)
		}
		if err := setup.selector.configureNetwork(setup.network); err != nil {
			t.Fatal(err)
		}
	}
	const host = "executor.example.test"
	choose := func(a *adaptiveSelector) *adaptivePick {
		first := a.chooseSocketLive(host, localdpi.TLS)
		if first.flow.MethodID != "pass" {
			t.Fatalf("bad baseline: %s", first.flow.MethodID)
		}
		return a.chooseSocketLive(host, localdpi.TLS)
	}
	vpnPick := choose(vpn)
	otherPick := choose(otherVPN)
	rootPick := choose(root)
	if vpnPick.flow != otherPick.flow || vpnPick.entryID != otherPick.entryID {
		t.Fatal("same-kind fixture must produce colliding flow IDs")
	}
	if vpnPick.flow.MethodID != "tlsrec-split" || rootPick.flow.MethodID != "split" {
		t.Fatal("wrong executor candidates", vpnPick.flow.MethodID, rootPick.flow.MethodID)
	}
	if pick := root.chooseSocketLive("udp:203.0.113.9", localdpi.QUIC); pick.flow.MethodID != "" {
		t.Fatal("unregistered QUIC inherited VPN candidates")
	}
	evidence := localdpi.SocketDownstream(adaptivePayloadThreshold)
	vpn.observeSocketEvidence(otherPick, evidence)
	vpn.observeSocketEvidence(rootPick, evidence)
	root.observeSocketEvidence(vpnPick, evidence)
	if vpn.entries[host].preferred != "" || root.entries[host].preferred != "" ||
		vpn.neural.export() != nil || root.neural.export() != nil {
		t.Fatal("foreign flow changed preference or model")
	}
	root.observeSocketEvidence(rootPick, evidence)
	if root.entries[host].preferred != "split" || root.neural.weights.ContextObservations[0] != 1 ||
		root.neural.weights.ContextObservations[3] != 0 || len(root.neural.export()) == 0 ||
		vpn.neural.export() != nil || otherVPN.neural.export() != nil {
		t.Fatal("ROOT observation escaped its model or network category")
	}
	vpn.observeSocketEvidence(vpnPick, evidence)
	if vpn.neural.weights.ContextObservations[3] != 1 ||
		vpn.neural.weights.ContextObservations[0] != 0 || otherVPN.neural.export() != nil {
		t.Fatal("VPN observation escaped its model or network category")
	}
}

func TestAdaptiveExecutorRetiresFlowsOnModelReplacement(t *testing.T) {
	a := newAdaptiveSelector(socketCapabilities)
	model := generatedTestModel(t, 32)
	if err := a.configureModel(model); err != nil {
		t.Fatal(err)
	}
	const host = "replacement.example.test"
	a.chooseSocketLive(host, localdpi.TLS)
	pick := a.chooseSocketLive(host, localdpi.TLS)
	if err := a.configureModel([]byte("invalid")); err == nil {
		t.Fatal("invalid model accepted")
	}
	evidence := localdpi.SocketDownstream(adaptivePayloadThreshold)
	a.observeSocketEvidence(pick, evidence)
	if len(a.neural.export()) == 0 {
		t.Fatal("rejected replacement invalidated a working flow")
	}
	if err := a.configureModel(model); err != nil {
		t.Fatal(err)
	}
	a.chooseSocketLive(host, localdpi.TLS)
	current := a.chooseSocketLive(host, localdpi.TLS)
	if current.entryID != pick.entryID || current.flow.Generation == pick.flow.Generation {
		t.Fatal("replacement must create a new generation")
	}
	a.observeSocketEvidence(pick, evidence)
	if a.neural.export() != nil || a.entries[host].preferred != "" {
		t.Fatal("old flow trained a replacement model")
	}
	a.observeSocketEvidence(current, evidence)
	if len(a.neural.export()) == 0 {
		t.Fatal("new-generation evidence rejected")
	}
}
