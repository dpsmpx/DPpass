//go:build windows

package bridge

import (
	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Сеть ПК для оболочки Windows (D-97, к D-79 и D-92): маршрут по
// умолчанию с наименьшей метрикой — не через адаптер DPpass — и есть ли
// этот адаптер. Так оболочка знает тип сети для учёта трафика, ключ сети
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

// Network — маршрут по умолчанию: интерфейс (его псевдоним Windows), шлюз и вид.
type Network struct {
	Alias   string
	Gateway string
	Kind    NetKind
}

// DefaultRoute — маршрут по умолчанию с наименьшей метрикой (маршрута и
// интерфейса), кроме адаптера tunAlias; ok=false — такого нет. tunUp —
// адаптер tunAlias сейчас поднят. Выбор — pickDefault.
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
		row := routeRow{alias: ifrow.Alias(), gateway: r.NextHop.Addr().String(), kind: kindOf(ifrow.Type)}
		if r.DestinationPrefix.PrefixLength == 0 {
			family := winipcfg.AddressFamily(windows.AF_INET)
			if r.DestinationPrefix.Prefix().Addr().Is6() {
				family = windows.AF_INET6
			}
			if ipif, e := r.InterfaceLUID.IPInterface(family); e == nil {
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
}

// pickDefault — маршрут по умолчанию с наименьшей метрикой, кроме адаптера
// tunAlias; любая строка адаптера значит, что он поднят. При равной метрике
// — первый в таблице: выбор не скачет между опросами.
func pickDefault(rows []routeRow, tunAlias string) (net Network, ok bool, tunUp bool) {
	best := ^uint64(0)
	for _, r := range rows {
		if r.alias == tunAlias {
			tunUp = true
			continue
		}
		if r.isDefault && r.metric < best {
			best = r.metric
			net = Network{Alias: r.alias, Gateway: r.gateway, Kind: r.kind}
			ok = true
		}
	}
	return net, ok, tunUp
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
