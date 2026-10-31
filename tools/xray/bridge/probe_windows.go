//go:build windows

package bridge

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
)

// Пробы проверки сети мимо туннеля на Windows (D-99, к D-79): сокет пробы
// привязывается к физическому интерфейсу маршрута по умолчанию так же, как
// ядро привязывает свои (`autoOutboundsInterface`, IP_UNICAST_IF), а имена
// резолвятся серверами DNS этого интерфейса сокетами с той же привязкой.
// Фильтр WFP «dns» ядра такие запросы пропускает: его жёсткое разрешение
// дано всему процессу ядра, а ядро живёт в процессе JVM
// (docs/research/WINDOWS_SHELL.md, §2.3).

// Номера опций — ws2ipdef.h; в golang.org/x/sys/windows их нет.
const (
	ipUnicastIf   = 31
	ipv6UnicastIf = 31
)

// ProbeInterface — интерфейс маршрута по умолчанию мимо адаптера tunAlias
// и его серверы DNS. Маршрута нет — отказ: пробы ушли бы в туннель.
func ProbeInterface(tunAlias string) (index uint32, dns []netip.Addr, err error) {
	n, ok, _, err := DefaultRoute(tunAlias)
	if err != nil {
		return 0, nil, err
	}
	if !ok {
		return 0, nil, fail(KindConfig, "маршрута по умолчанию мимо адаптера %s нет", tunAlias)
	}
	servers, err := n.LUID.DNS()
	if err != nil {
		return 0, nil, err
	}
	return n.Index, servers, nil
}

// BindToInterface привязывает сокет handle к интерфейсу index: IPv4 —
// IP_UNICAST_IF (номер — в сетевом порядке байт), сокету IPv6 ещё и
// IPV6_UNICAST_IF. Сокеты JDK на Windows — двойного стека (IPv6 с
// адресами IPv4 внутри), поэтому у сокета IPv6 ставятся обе: так же
// поступает ядро (proxy/tun, setinterface). Ошибка любой опции — отказ:
// непривязанный сокет ушёл бы в туннель.
func BindToInterface(handle uintptr, index uint32) error {
	return systemSockopts.bind(windows.Handle(handle), index)
}

// sockopts — опции сокета; в тестах — подмена: IP_UNICAST_IF Wine 9.0 не
// поддерживает (WSAEOPNOTSUPP), системный вызов проверяется на ПК автора.
type sockopts struct {
	set func(h windows.Handle, level, opt, value int) error
	get func(h windows.Handle, level, opt int) (int, error)
}

var systemSockopts = sockopts{set: windows.SetsockoptInt, get: windows.GetsockoptInt}

func (o sockopts) bind(h windows.Handle, index uint32) error {
	if index == 0 {
		return fail(KindContract, "номер интерфейса 0")
	}
	if v6, err := o.isIPv6(h); err != nil {
		return err
	} else if v6 {
		if err := o.set(h, windows.IPPROTO_IPV6, ipv6UnicastIf, int(index)); err != nil {
			return err
		}
	}
	return o.set(h, windows.IPPROTO_IP, ipUnicastIf, networkOrder(index))
}

// networkOrder — номер интерфейса для IP_UNICAST_IF: те же 4 байта в
// сетевом порядке, прочитанные как число машины (htonl).
func networkOrder(index uint32) int {
	var be [4]byte
	binary.BigEndian.PutUint32(be[:], index)
	return int(int32(binary.NativeEndian.Uint32(be[:])))
}

// isIPv6 — сокет семейства IPv6: только у него есть IPV6_V6ONLY. Иной
// отказ, чем «не та опция», — ошибка самого сокета.
func (o sockopts) isIPv6(h windows.Handle) (bool, error) {
	_, err := o.get(h, windows.IPPROTO_IPV6, windows.IPV6_V6ONLY)
	switch err {
	case nil:
		return true, nil
	case windows.WSAENOPROTOOPT, windows.WSAEINVAL:
		return false, nil
	}
	return false, err
}

// ResolveVia — адреса имени host у серверов DNS servers сокетами,
// привязанными к интерфейсу index: первый сервер, ответивший без отказа.
// Серверов нет — отказ, а не системный резолвер: его запрос ушёл бы в
// туннель.
func ResolveVia(host string, servers []netip.Addr, index uint32, timeout time.Duration) ([]string, error) {
	ports := make([]netip.AddrPort, 0, len(servers))
	for _, s := range servers {
		ports = append(ports, netip.AddrPortFrom(s, 53))
	}
	return resolveVia(host, ports, index, timeout, "", func(fd uintptr) error { return BindToInterface(fd, index) })
}

// resolveVia — ResolveVia с портами серверов, привязкой bind и, если
// transport не пуст, одним транспортом запросов. Тест поднимает свой сервер
// на loopback по TCP: сокет UDP Go в Wine 9.0 не создать (SIO_UDP_CONNRESET
// — «не поддерживается»), а IP_UNICAST_IF Wine не знает.
func resolveVia(host string, servers []netip.AddrPort, index uint32, timeout time.Duration, transport string, bind func(fd uintptr) error) ([]string, error) {
	if host == "" || timeout <= 0 || index == 0 {
		return nil, fail(KindContract, "имя %q, срок %v, интерфейс %d", host, timeout, index)
	}
	if len(servers) == 0 {
		return nil, fail(KindConfig, "у интерфейса %d нет серверов DNS", index)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	var last error
	for _, s := range servers {
		r := &net.Resolver{PreferGo: true, Dial: boundDial(s, transport, bind)}
		addrs, err := r.LookupIPAddr(ctx, host)
		if err == nil {
			out := make([]string, 0, len(addrs))
			for _, a := range addrs {
				out = append(out, a.IP.String())
			}
			return out, nil
		}
		last = err
	}
	return nil, last
}

// boundDial — соединение резолвера Go с сервером server (адрес из системы
// резолвер подставит свой, он не нужен) сокетом с привязкой bind;
// transport, если не пуст, заменяет транспорт, который просит резолвер.
func boundDial(server netip.AddrPort, transport string, bind func(fd uintptr) error) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		if transport != "" {
			network = transport
		}
		d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var bindErr error
			if err := c.Control(func(fd uintptr) { bindErr = bind(fd) }); err != nil {
				return err
			}
			return bindErr
		}}
		return d.DialContext(ctx, network, server.String())
	}
}
