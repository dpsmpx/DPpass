//go:build windows

package bridge

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Сеть ПК для оболочки Windows (D-97, к D-79 и D-92): маршрут по
// умолчанию, который выбрало бы для своих сокетов ядро (pickDefault), — не
// через адаптер DPpass — и есть ли этот адаптер. Так оболочка знает тип сети для учёта трафика, ключ сети
// для памяти режима (D-64) и поднят ли туннель, не обращаясь к командам
// Windows.

// NetKind — вид интерфейса; числа — договор с desktop.WindowsHost (Kotlin).
type NetKind uint8

const (
	NetOther    NetKind = 0
	NetEthernet NetKind = 1
	NetWifi     NetKind = 2
	NetMobile   NetKind = 3
)

// Network — маршрут по умолчанию: интерфейс (его псевдоним Windows), шлюз и
// вид; Index и LUID — для проб мимо туннеля (D-99).
type Network struct {
	Alias   string
	Gateway string
	Kind    NetKind
	Index   uint32
	LUID    winipcfg.LUID
}

// DefaultRoute — маршрут по умолчанию мимо адаптера tunAlias, который
// выбрало бы для своих сокетов ядро (`autoOutboundsInterface: "auto"`);
// ok=false — такого нет. tunUp — адаптер tunAlias сейчас поднят. Выбор —
// pickDefault.
func DefaultRoute(tunAlias string) (net Network, ok bool, tunUp bool, err error) {
	table, err := winipcfg.GetIPForwardTable2(windows.AF_UNSPEC)
	if err != nil {
		return Network{}, false, false, err
	}
	rows := make([]routeRow, 0, len(table))
	for i := range table {
		r := &table[i]
		ifrow, e := r.InterfaceLUID.Interface()
		if e != nil || ifrow.OperStatus != winipcfg.IfOperStatusUp {
			continue
		}
		row := routeRow{alias: ifrow.Alias(), gateway: r.NextHop.Addr().String(), kind: kindOf(ifrow.Type), index: ifrow.InterfaceIndex, luid: r.InterfaceLUID}
		if r.DestinationPrefix.PrefixLength == 0 {
			// Метрика — как у ядра: маршрута плюс интерфейса IPv4, а нет IPv4 — IPv6.
			ipif, e := r.InterfaceLUID.IPInterface(windows.AF_INET)
			if e != nil {
				ipif, e = r.InterfaceLUID.IPInterface(windows.AF_INET6)
			}
			if e == nil {
				row.isDefault = true
				row.metric = uint64(r.Metric) + uint64(ipif.Metric)
			}
		}
		rows = append(rows, row)
	}
	net, ok, tunUp = pickDefault(rows, tunAlias)
	return net, ok, tunUp, nil
}

// routeRow — строка таблицы маршрутов поднятого интерфейса: isDefault —
// маршрут по умолчанию (/0), metric — его метрика вместе с метрикой
// интерфейса.
type routeRow struct {
	alias     string
	gateway   string
	kind      NetKind
	isDefault bool
	metric    uint64
	index     uint32
	luid      winipcfg.LUID
}

// pickDefault — интерфейс, к которому ядро привяжет свои сокеты, кроме
// адаптера tunAlias (Xray 26.9.30, `proxy/tun/tun_windows.go`,
// `findOutboundInterface`): есть маршрут по умолчанию через Wi-Fi — Wi-Fi с
// наименьшей метрикой среди Wi-Fi, даже если у другого метрика меньше;
// нет — наименьшая метрика. Тот же выбор нужен оболочке: пробы мимо туннеля
// (D-99), вид сети для учёта трафика и ключ сети (D-97) — о той сети, по
// которой идёт трафик ядра. Любая строка адаптера значит, что он поднят. При
// равной метрике — первый в таблице: выбор не скачет между опросами.
func pickDefault(rows []routeRow, tunAlias string) (net Network, ok bool, tunUp bool) {
	var best, bestWifi *routeRow
	for i := range rows {
		r := &rows[i]
		if r.alias == tunAlias {
			tunUp = true
			continue
		}
		if !r.isDefault {
			continue
		}
		if r.kind == NetWifi {
			if bestWifi == nil || r.metric < bestWifi.metric {
				bestWifi = r
			}
			continue
		}
		if best == nil || r.metric < best.metric {
			best = r
		}
	}
	if bestWifi != nil {
		best = bestWifi
	}
	if best == nil {
		return Network{}, false, tunUp
	}
	return Network{Alias: best.alias, Gateway: best.gateway, Kind: best.kind, Index: best.index, LUID: best.luid}, true, tunUp
}

func kindOf(t winipcfg.IfType) NetKind {
	switch uint32(t) {
	case windows.IF_TYPE_ETHERNET_CSMACD:
		return NetEthernet
	case windows.IF_TYPE_IEEE80211:
		return NetWifi
	case ifTypeWwanPP, ifTypeWwanPP2:
		return NetMobile
	}
	return NetOther
}

// Типы интерфейсов мобильной сети (IANA ifType: wwanPP 243, wwanPP2 244).
const (
	ifTypeWwanPP  = 243
	ifTypeWwanPP2 = 244
)
