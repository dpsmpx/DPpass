//go:build linux && !android

package bridge

import (
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Имя сервера профиля резолвится мимо туннеля (D-74): заглушка
// systemd-resolved на loopback заменяется сервером сети, остальное — как есть.
func TestResolverUpstream(t *testing.T) {
	conf := func(text string) func(string) ([]byte, error) {
		return func(path string) ([]byte, error) {
			if path != systemResolvConf {
				t.Fatalf("читает %s, а не %s", path, systemResolvConf)
			}
			return []byte(text), nil
		}
	}
	missing := func(string) ([]byte, error) { return nil, os.ErrNotExist }
	cases := []struct {
		name, address string
		read          func(string) ([]byte, error)
		want          string
	}{
		{"сервер сети — как есть", "192.168.1.1:53", missing, "192.168.1.1:53"},
		{"IPv6 сети — как есть", "[fe80::1%wlan0]:53", missing, "[fe80::1%wlan0]:53"},
		{"заглушка → первый сервер сети", "127.0.0.53:53",
			conf("# комментарий\nnameserver 127.0.0.1\nnameserver 192.0.2.53\nnameserver 198.51.100.53\n"), "192.0.2.53:53"},
		{"заглушка → IPv6 сети", "127.0.0.53:53", conf("nameserver ::1\nnameserver 2001:db8::53\n"), "[2001:db8::53]:53"},
		{"заглушка IPv6 → сервер сети", "[::1]:53", conf("nameserver 192.0.2.53\n"), "192.0.2.53:53"},
		{"порт сохраняется", "127.0.0.53:5353", conf("nameserver 192.0.2.53\n"), "192.0.2.53:5353"},
		{"нет файла — заглушка как есть", "127.0.0.53:53", missing, "127.0.0.53:53"},
		{"в файле только loopback — как есть", "127.0.0.53:53", conf("nameserver 127.0.0.1\n"), "127.0.0.53:53"},
		{"мусор в файле пропускается", "127.0.0.53:53", conf("nameserver\nnameserver не-адрес\nsearch lan\nnameserver 192.0.2.53\n"), "192.0.2.53:53"},
		{"адрес без порта — как есть", "127.0.0.53", missing, "127.0.0.53"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := resolverUpstream(c.address, c.read); got != c.want {
				t.Fatalf("resolverUpstream(%q) = %q, ждали %q", c.address, got, c.want)
			}
		})
	}
}

// Резолвер с меткой: метку поставить не вышло — соединения нет, а не
// запрос без метки (он ушёл бы в туннель). Без CAP_NET_ADMIN SO_MARK
// отвечает EPERM — это и проверяется; с ней — соединение с меткой.
func TestMarkedDialRefusesUnmarkedSocket(t *testing.T) {
	ln, err := netListenUDP()
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	dial := markedDial(0x7350, func(string) ([]byte, error) { return nil, os.ErrNotExist })
	conn, err := dial(t.Context(), "udp", ln.LocalAddr().String())
	if hasNetAdmin() {
		if err != nil {
			t.Fatalf("с CAP_NET_ADMIN соединение должно быть: %v", err)
		}
		_ = conn.Close()
		return
	}
	if err == nil {
		_ = conn.Close()
		t.Fatal("без CAP_NET_ADMIN метка не ставится, а соединение есть")
	}
	if !errors.Is(err, unix.EPERM) {
		t.Fatalf("ждали EPERM, а %v", err)
	}
}

// Копию fd, которая не TUN, releaseCoreTun не закрывает: закрывается
// только копия того же TUN, что у платформы.
func TestReleaseCoreTunLeavesForeignFd(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	releaseCoreTun(p[0], p[1])
	if _, err := unix.FcntlInt(uintptr(p[0]), unix.F_GETFD, 0); err != nil {
		t.Fatalf("чужой fd закрыт: %v", err)
	}
}

func TestOpenTunRejectsBadNames(t *testing.T) {
	for _, name := range []string{"", "dppass%d", "a/b", "слишком-длинное-имя"} {
		if fd, err := OpenTun(name); err == nil {
			_ = unix.Close(fd)
			t.Fatalf("имя %q принято", name)
		}
	}
}

// Проверка сети на ПК (D-79) резолвит через резолвер моста: адреса —
// строками; пустое имя или срок — нарушение договора, а не запрос.
func TestResolveReturnsAddressesAndRefusesBadCalls(t *testing.T) {
	addrs, err := Resolve("localhost", 2*time.Second)
	if err != nil {
		t.Fatalf("localhost: %v", err)
	}
	for _, a := range addrs {
		if ip := net.ParseIP(a); ip == nil || !ip.IsLoopback() {
			t.Fatalf("localhost — %q, ждали loopback", a)
		}
	}
	for _, c := range []struct {
		host    string
		timeout time.Duration
	}{{"", time.Second}, {"localhost", 0}} {
		var be *Error
		if _, err := Resolve(c.host, c.timeout); !errors.As(err, &be) || be.Kind != KindContract {
			t.Fatalf("Resolve(%q, %v) = %v, ждали KindContract", c.host, c.timeout, err)
		}
	}
	if _, err := Resolve("name.invalid", 2*time.Second); err == nil {
		t.Fatal("имя в .invalid резолвится")
	}
}

func netListenUDP() (*net.UDPConn, error) {
	return net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
}

// hasNetAdmin — есть ли у процесса CAP_NET_ADMIN (бит 12 CapEff).
func hasNetAdmin() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if v, ok := strings.CutPrefix(line, "CapEff:"); ok {
			caps, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
			return err == nil && caps&(1<<unix.CAP_NET_ADMIN) != 0
		}
	}
	return false
}
