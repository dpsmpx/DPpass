//go:build windows

package bridge

import (
	"bytes"
	"strings"
	"testing"
)

// Договор Start на Windows (D-97): fd и защитника нет — адаптер и
// привязку сокетов делает вход TUN ядра.
func TestWindowsTunContract(t *testing.T) {
	tun := &tunInbound{MTU: 1500}
	if err := checkTun(tun, Tun{FD: -1}, nil); err != nil {
		t.Fatalf("TUN без fd и без защитника — так и задумано: %v", err)
	}
	if err := checkTun(tun, Tun{FD: 3}, nil); err == nil {
		t.Fatal("fd TUN на Windows принят")
	}
	if err := checkTun(nil, Tun{FD: -1}, allowAll{}); err == nil {
		t.Fatal("защитник сокетов на Windows принят")
	}
}

// Ключ под DPAPI читается обратно, а без добавки DPpass — нет.
func TestDpapiRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	sealed, err := Protect(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, key) {
		t.Fatal("блок DPAPI содержит ключ открыто")
	}
	plain, err := Unprotect(sealed)
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatalf("Unprotect: %x, %v", plain, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Unprotect(sealed); err == nil {
		t.Fatal("испорченный блок расшифрован")
	}
	if _, err := Protect(nil); err == nil {
		t.Fatal("пустые данные приняты")
	}
}

// Политика моста на Windows (D-97): вход TUN — как пишет компилятор DPpass
// (XrayCompiler.systemTunSettings), иначе отказ.
func TestWindowsPolicyAcceptsOnlyCompilerSystemTun(t *testing.T) {
	config := func(settings string) []byte {
		return []byte(`{"inbounds": [{"tag": "tun-in", "protocol": "tun", "settings": {` + settings + `}}], "outbounds": [{"protocol": "freedom"}]}`)
	}
	const good = `"name": "dppass0", "mtu": 1500, "gateway": ["172.19.0.1/30"], "dns": ["172.19.0.2"], ` +
		`"autoSystemRoutingTable": ["0.0.0.0/0", "::/0"], "autoOutboundsInterface": "auto", "autoSystemWfpBlockLeak": ["dns", "misconfigtun"]`
	if _, tunIn, err := build(config(good)); err != nil || tunIn == nil {
		t.Fatalf("вход TUN компилятора должен проходить: %v", err)
	}
	bad := map[string]string{
		"чужое имя":         strings.Replace(good, `"dppass0"`, `"other"`, 1),
		"без маршрутов":     `"name": "dppass0", "mtu": 1500, "gateway": ["172.19.0.1/30"], "dns": ["172.19.0.2"]`,
		"без фильтра DNS":   strings.Replace(good, `["dns", "misconfigtun"]`, `["misconfigtun"]`, 1),
		"без misconfigtun":  strings.Replace(good, `["dns", "misconfigtun"]`, `["dns"]`, 1),
		"интерфейс задан":   strings.Replace(good, `"autoOutboundsInterface": "auto"`, `"autoOutboundsInterface": "Ethernet"`, 1),
		"без адаптера ядра": `"name": "dppass0", "mtu": 1500`,
	}
	for name, settings := range bad {
		if _, _, err := build(config(settings)); err == nil || !strings.Contains(err.Error(), "мост:") {
			t.Errorf("%s: политика должна отвергнуть вход TUN, получено %v", name, err)
		}
	}
}
