//go:build windows

package bridge

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
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
	var be *Error
	if _, err := Unprotect(sealed); !errors.As(err, &be) || be.Kind != KindConfig {
		t.Fatalf("испорченный блок — ключ потерян (KindConfig), получено %v", err)
	}
	// Временный отказ службы — не потеря: данные не сбрасываются.
	if unprotectLost(windows.RPC_S_SERVER_UNAVAILABLE) || !unprotectLost(windows.Errno(windows.NTE_BAD_KEY_STATE)) {
		t.Fatal("отказы DPAPI разобраны не так")
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

// Маршрут по умолчанию (D-97): наименьшая метрика, адаптер DPpass в маршрут
// не попадает, но значит «туннель поднят»; вид интерфейса — по его типу.
// Таблицу маршрутов Wine не отдаёт (GetIPForwardTable2 — «Request not
// supported»): системный вызов проверяется на ПК с Windows
// (docs/research/WINDOWS_SHELL.md, §6), здесь — выбор по таблице.
func TestDefaultRouteSkipsOwnAdapterAndKnowsKinds(t *testing.T) {
	rows := []routeRow{
		{alias: "Ethernet", gateway: "192.0.2.1", kind: NetEthernet, isDefault: true, metric: 35},
		{alias: tunName, gateway: "0.0.0.0", isDefault: true, metric: 0},
		{alias: "Wi-Fi", gateway: "198.51.100.1", kind: NetWifi, isDefault: true, metric: 25},
		{alias: "Wi-Fi", gateway: "0.0.0.0", kind: NetWifi},
		{alias: "Cellular", gateway: "203.0.113.1", kind: NetMobile, isDefault: true, metric: 25},
	}
	net, ok, up := pickDefault(rows, tunName)
	if !ok || !up || net != (Network{Alias: "Wi-Fi", Gateway: "198.51.100.1", Kind: NetWifi}) {
		t.Fatalf("ждали Wi-Fi и поднятый адаптер, получено %+v ok=%v up=%v", net, ok, up)
	}
	if _, ok, up := pickDefault(rows[1:2], tunName); ok || !up {
		t.Fatalf("только адаптер DPpass — маршрута нет, туннель поднят: ok=%v up=%v", ok, up)
	}
	if _, ok, up := pickDefault(rows[3:4], tunName); ok || up {
		t.Fatalf("без маршрута /0 — сети нет: ok=%v up=%v", ok, up)
	}
	for typ, want := range map[uint32]NetKind{
		windows.IF_TYPE_ETHERNET_CSMACD: NetEthernet,
		windows.IF_TYPE_IEEE80211:       NetWifi,
		ifTypeWwanPP:                    NetMobile,
		windows.IF_TYPE_PPP:             NetOther,
	} {
		if got := kindOf(winipcfg.IfType(typ)); got != want {
			t.Errorf("тип %d: %d, ждали %d", typ, got, want)
		}
	}
}
