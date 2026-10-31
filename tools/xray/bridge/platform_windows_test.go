//go:build windows

package bridge

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
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

// Тема приложений (D-97): значение пользователя читается как есть; нет
// параметра — «не узнать». Прежнее значение возвращается на место.
func TestAppsUseLightThemeReadsUserValue(t *testing.T) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, personalizeKey, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		t.Fatal(err)
	}
	defer k.Close()
	old, _, had := k.GetIntegerValue("AppsUseLightTheme")
	defer func() {
		if had == nil {
			_ = k.SetDWordValue("AppsUseLightTheme", uint32(old))
		} else {
			_ = k.DeleteValue("AppsUseLightTheme")
		}
	}()
	for _, v := range []uint32{0, 1} {
		if err := k.SetDWordValue("AppsUseLightTheme", v); err != nil {
			t.Fatal(err)
		}
		if light, ok := AppsUseLightTheme(); !ok || light != (v == 1) {
			t.Fatalf("AppsUseLightTheme=%d: light=%v ok=%v", v, light, ok)
		}
	}
	if err := k.DeleteValue("AppsUseLightTheme"); err != nil {
		t.Fatal(err)
	}
	if _, ok := AppsUseLightTheme(); ok {
		t.Fatal("параметра нет — тема не узнана, а не «тёмная»")
	}
}

// Сокет пробы мимо туннеля (D-99): у сокета IPv6 (двойного стека JDK) —
// IPV6_UNICAST_IF и IP_UNICAST_IF, у IPv4 — одна; номер IPv4 — в сетевом
// порядке байт; ошибка опции или чтения семейства — отказ; номер 0 — отказ
// без вызовов. Опции — подменой: IP_UNICAST_IF Wine 9.0 не поддерживает
// (WSAEOPNOTSUPP), системный вызов — ПК автора.
func TestBindToInterfaceSetsUnicastIfForBothFamilies(t *testing.T) {
	type call struct{ level, opt, value int }
	fake := func(family error, setErr error) (sockopts, *[]call) {
		var calls []call
		return sockopts{
			set: func(_ windows.Handle, level, opt, value int) error {
				calls = append(calls, call{level, opt, value})
				return setErr
			},
			get: func(windows.Handle, int, int) (int, error) { return 0, family },
		}, &calls
	}
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], 7)
	v4value := int(int32(binary.NativeEndian.Uint32(be[:])))

	o, calls := fake(nil, nil)
	if err := o.bind(1, 7); err != nil {
		t.Fatal(err)
	}
	if want := []call{{windows.IPPROTO_IPV6, ipv6UnicastIf, 7}, {windows.IPPROTO_IP, ipUnicastIf, v4value}}; !slices.Equal(*calls, want) {
		t.Fatalf("сокет IPv6: %v, ждали %v", *calls, want)
	}
	o, calls = fake(windows.WSAENOPROTOOPT, nil)
	if err := o.bind(1, 7); err != nil || !slices.Equal(*calls, []call{{windows.IPPROTO_IP, ipUnicastIf, v4value}}) {
		t.Fatalf("сокет IPv4: %v, %v", *calls, err)
	}
	if o, _ := fake(nil, windows.WSAEOPNOTSUPP); o.bind(1, 7) == nil {
		t.Fatal("отказ опции не стал отказом привязки")
	}
	if o, _ := fake(windows.WSAENOTSOCK, nil); o.bind(1, 7) == nil {
		t.Fatal("ошибка сокета прочитана как «IPv4»")
	}
	if o, calls := fake(nil, nil); o.bind(1, 0) == nil || len(*calls) != 0 {
		t.Fatal("номер интерфейса 0 принят")
	}
}

// Резолв пробы (D-99): спрашивается данный сервер сокетом с привязкой, а не
// системный резолвер; привязка не встала — отказ, сервер не спрошен; без
// серверов — отказ, а не запрос в туннель. Сервер — свой на loopback, по
// TCP: UDP Go в Wine 9.0 не создать.
func TestResolveViaAsksGivenServerOverBoundSocket(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	var asked atomic.Int32
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			asked.Add(1)
			go serveTCPDNS(c, [4]byte{192, 0, 2, 7})
		}
	}()
	server := netip.MustParseAddrPort(ln.Addr().String())
	var bound atomic.Int32
	bind := func(uintptr) error { bound.Add(1); return nil }
	got, err := resolveVia("probe.example.com", []netip.AddrPort{server}, 7, 5*time.Second, "tcp", bind)
	if err != nil || len(got) != 1 || got[0] != "192.0.2.7" || bound.Load() == 0 {
		t.Fatalf("ждали 192.0.2.7 от своего сервера сокетом с привязкой, получено %v, %v, привязок %d", got, err, bound.Load())
	}
	before := asked.Load()
	refused := func(uintptr) error { return windows.WSAEOPNOTSUPP }
	if _, err := resolveVia("probe.example.com", []netip.AddrPort{server}, 7, time.Second, "tcp", refused); err == nil {
		t.Fatal("привязка не встала, а имя разрешено")
	}
	if asked.Load() != before {
		t.Fatal("сервер спрошен сокетом без привязки")
	}
	if _, err := ResolveVia("probe.example.com", nil, 7, time.Second); err == nil {
		t.Fatal("без серверов интерфейса — не отказ")
	}
	if _, err := ResolveVia("probe.example.com", []netip.Addr{server.Addr()}, 0, time.Second); err == nil {
		t.Fatal("интерфейс 0 принят")
	}
}

// serveTCPDNS — запросы DNS по TCP (длина двумя байтами перед сообщением).
func serveTCPDNS(c net.Conn, ip [4]byte) {
	defer func() { _ = c.Close() }()
	for {
		var n [2]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return
		}
		q := make([]byte, binary.BigEndian.Uint16(n[:]))
		if _, err := io.ReadFull(c, q); err != nil {
			return
		}
		a := answerA(q, ip)
		if a == nil {
			return
		}
		binary.BigEndian.PutUint16(n[:], uint16(len(a)))
		if _, err := c.Write(append(n[:], a...)); err != nil {
			return
		}
	}
}

// answerA — ответ на запрос q: на A — адрес ip, на прочее — без записей.
// Раздел дополнительных записей запроса (OPT) в ответ не идёт.
func answerA(q []byte, ip [4]byte) []byte {
	if len(q) < 12 {
		return nil
	}
	end := 12
	for end < len(q) && q[end] != 0 {
		end += int(q[end]) + 1
	}
	end += 5 // ноль имени, тип и класс
	if end > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[end-4 : end-2])
	out := append([]byte{}, q[:end]...)
	out[2] |= 0x80 // QR
	out[3] = 0x80  // RA, NOERROR
	binary.BigEndian.PutUint16(out[8:10], 0)
	binary.BigEndian.PutUint16(out[10:12], 0)
	if qtype != 1 {
		binary.BigEndian.PutUint16(out[6:8], 0)
		return out
	}
	binary.BigEndian.PutUint16(out[6:8], 1)
	out = append(out, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4)
	return append(out, ip[:]...)
}

