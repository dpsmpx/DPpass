//go:build windows

package bridge

import (
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Сети ПК для устройства раздачи на Windows (D-102, к D-85): где искать
// раздающий телефон — шлюзы маршрутов по умолчанию в частных адресах, — и
// адреса IPv4 поднятых интерфейсов: устройство с явным адресом ищется в
// подсети одного из них. Адаптер DPpass не в счёт.

// RelayMedium — по какой сети ПК подключён к телефону; числа — договор с
// desktop.RelayNetworks.Medium (Kotlin). Только подпись в окне: адрес
// устройства всё равно проверяется входом SOCKS5 с паролем.
type RelayMedium uint8

const (
	RelayWired     RelayMedium = 0
	RelayWifi      RelayMedium = 1
	RelayUSB       RelayMedium = 2
	RelayBluetooth RelayMedium = 3
)

// RelayNet — поднятый интерфейс: номер, псевдоним (по нему ядро привязывает
// сокеты, D-102), вид, частные шлюзы его маршрутов по умолчанию и адреса
// IPv4 с длиной префикса.
type RelayNet struct {
	Index    uint32
	Alias    string
	Medium   RelayMedium
	Gateways []netip.Addr
	Prefixes []netip.Prefix
}

// RelayNetworks — поднятые интерфейсы ПК, кроме адаптера tunAlias, с их
// шлюзами и адресами IPv4. Порядок — по номеру интерфейса.
func RelayNetworks(tunAlias string) ([]RelayNet, error) {
	routes, err := winipcfg.GetIPForwardTable2(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	table, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	rows := map[winipcfg.LUID]*relayRow{}
	row := func(luid winipcfg.LUID) *relayRow {
		if r, ok := rows[luid]; ok {
			return r
		}
		r := &relayRow{}
		if ifrow, err := luid.Interface(); err == nil {
			r.up = ifrow.OperStatus == winipcfg.IfOperStatusUp
			r.loopback = uint32(ifrow.Type) == windows.IF_TYPE_SOFTWARE_LOOPBACK
			r.net = RelayNet{Index: ifrow.InterfaceIndex, Alias: ifrow.Alias(), Medium: mediumOf(ifrow.Type, ifrow.PhysicalMediumType, ifrow.Description())}
		}
		rows[luid] = r
		return r
	}
	for i := range routes {
		rt := &routes[i]
		if rt.DestinationPrefix.PrefixLength == 0 {
			r := row(rt.InterfaceLUID)
			r.gateways = append(r.gateways, rt.NextHop.Addr())
		}
	}
	for i := range table {
		a := &table[i]
		if a.DadState == winipcfg.DadStatePreferred {
			r := row(a.InterfaceLUID)
			r.prefixes = append(r.prefixes, netip.PrefixFrom(a.Address.Addr(), int(a.OnLinkPrefixLength)))
		}
	}
	list := make([]relayRow, 0, len(rows))
	for _, r := range rows {
		list = append(list, *r)
	}
	return pickRelayNets(list, tunAlias), nil
}

// relayRow — интерфейс из таблиц маршрутов и адресов, ещё не отобранный.
type relayRow struct {
	net      RelayNet
	up       bool
	loopback bool
	gateways []netip.Addr
	prefixes []netip.Prefix
}

// pickRelayNets — поднятые интерфейсы, кроме loopback, tunAlias и тех, о
// которых Windows не ответила (номер 0); шлюзы — только частные IPv4 (устройство
// раздачи — шлюз сети телефона, публичный шлюз — провайдер), адреса —
// только IPv4. Без шлюзов и адресов интерфейс не нужен.
func pickRelayNets(rows []relayRow, tunAlias string) []RelayNet {
	var out []RelayNet
	for _, r := range rows {
		if !r.up || r.loopback || r.net.Index == 0 || r.net.Alias == tunAlias {
			continue
		}
		n := r.net
		n.Gateways, n.Prefixes = nil, nil
		for _, g := range r.gateways {
			if g.Is4() && g.IsPrivate() && !slices.Contains(n.Gateways, g) {
				n.Gateways = append(n.Gateways, g)
			}
		}
		for _, p := range r.prefixes {
			if p.IsValid() && p.Addr().Is4() && !slices.Contains(n.Prefixes, p) {
				n.Prefixes = append(n.Prefixes, p)
			}
		}
		if len(n.Gateways) == 0 && len(n.Prefixes) == 0 {
			continue
		}
		out = append(out, n)
	}
	slices.SortFunc(out, func(a, b RelayNet) int { return int(a.Index) - int(b.Index) })
	return out
}

// mediumOf — вид сети для подписи: Wi-Fi — по типу интерфейса, Bluetooth
// (PAN) — по физической среде, USB-модем телефона — по описанию адаптера
// RNDIS («Remote NDIS»): иного признака USB таблица интерфейсов не даёт.
func mediumOf(t winipcfg.IfType, physical winipcfg.NdisPhysicalMedium, description string) RelayMedium {
	switch {
	case uint32(t) == windows.IF_TYPE_IEEE80211 || physical == winipcfg.NdisPhysicalMediumNative802_11 || physical == winipcfg.NdisPhysicalMediumWirelessLan:
		return RelayWifi
	case physical == winipcfg.NdisPhysicalMediumBluetooth:
		return RelayBluetooth
	case strings.Contains(strings.ToLower(description), "remote ndis"):
		return RelayUSB
	}
	return RelayWired
}
