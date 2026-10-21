//go:build linux && !android

package bridge

// Функции оболочки Linux (D-74): то, что на Android даёт VpnService, —
// открыть TUN и вывести сокет из туннеля — на ПК делает мост. Права —
// CAP_NET_ADMIN у процесса приложения; без них — отказ с errno.

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// OpenTun открывает TUN name: IFF_TUN | IFF_NO_PI (так его ждёт вход TUN
// Xray), не постоянный — с последним fd исчезают устройство и его
// маршруты. Имя с «%» отвергается: ядро Linux подставило бы номер, и
// устройство не совпало бы с именем во входе TUN конфигурации.
func OpenTun(name string) (int, error) {
	if name == "" || len(name) >= unix.IFNAMSIZ || strings.ContainsAny(name, "%/") {
		return -1, fail(KindContract, "имя TUN %q не подходит", name)
	}
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	ifr, err := unix.NewIfreq(name)
	if err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	ifr.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if err := unix.IoctlIfreq(fd, unix.TUNSETIFF, ifr); err != nil {
		_ = unix.Close(fd)
		return -1, err
	}
	return fd, nil
}

// CloseFd закрывает fd, открытый OpenTun: из JVM его иначе не закрыть.
func CloseFd(fd int) error {
	if fd < 0 {
		return fail(KindContract, "fd %d", fd)
	}
	return unix.Close(fd)
}

// MarkSocket ставит метку SO_MARK: правило метки ведёт сокет мимо таблицы
// туннеля (D-74, T4).
func MarkSocket(fd, mark int) error {
	return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_MARK, mark)
}

// systemResolvConf — серверы сети, которые спрашивает systemd-resolved;
// /etc/resolv.conf при нём указывает на его заглушку на loopback.
const systemResolvConf = "/run/systemd/resolve/resolv.conf"

// MarkResolver заменяет резолвер Go процесса: имя сервера профиля Xray
// отдаёт системному dialer, а тот — net.DefaultResolver (D-29). Без метки
// запрос ушёл бы правилом порта 53 в туннель, то есть в само ядро, ещё не
// подключённое к серверу. Резолвер — встроенный Go (не cgo: тот спросил бы
// systemd-resolved, а его запросы меток не несут), серверы — из
// /etc/resolv.conf, вместо заглушки на loopback — серверы сети.
func MarkResolver(mark int) {
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: markedDial(mark, os.ReadFile)}
}

func markedDial(mark int, read func(string) ([]byte, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{Control: func(_, _ string, c syscall.RawConn) error {
			var markErr error
			if err := c.Control(func(fd uintptr) { markErr = MarkSocket(int(fd), mark) }); err != nil {
				return err
			}
			// Без метки — отказ, а не запрос в туннель.
			return markErr
		}}
		return d.DialContext(ctx, network, resolverUpstream(address, read))
	}
}

// resolverUpstream — куда на самом деле слать запрос к серверу address
// («адрес:порт» из /etc/resolv.conf): заглушка на loopback заменяется
// первым сервером сети из systemResolvConf; нет его — address как есть.
func resolverUpstream(address string, read func(string) ([]byte, error)) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return address
	}
	ip, err := netip.ParseAddr(host)
	if err != nil || !ip.Unmap().IsLoopback() {
		return address
	}
	data, err := read(systemResolvConf)
	if err != nil {
		return address
	}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		up, err := netip.ParseAddr(f[1])
		if err != nil || up.Unmap().IsLoopback() {
			continue
		}
		return net.JoinHostPort(f[1], port)
	}
	return address
}
