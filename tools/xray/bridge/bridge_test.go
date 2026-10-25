//go:build linux

package bridge

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

// cfg — конфигурация в духе компилятора DPpass: журнал выключен,
// счётчики исходящего proxy включены, исходящий proxy — freedom (без
// сервера: в тестах моста соединяться не с кем), входы — из аргумента.
func cfg(inbounds string, extra ...string) []byte {
	parts := []string{
		`"log": {"loglevel": "none"}`,
		`"stats": {}`,
		`"policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}}`,
		`"inbounds": [` + inbounds + `]`,
		`"outbounds": [{"tag": "proxy", "protocol": "freedom"}, {"tag": "block", "protocol": "blackhole"}]`,
	}
	parts = append(parts, extra...)
	return []byte("{" + strings.Join(parts, ",") + "}")
}

const tunIn = `{"tag": "tun-in", "protocol": "tun", "settings": {"mtu": 1500}}`

func kindOf(t *testing.T, err error) Kind {
	t.Helper()
	var be *Error
	if !errors.As(err, &be) {
		t.Fatalf("ожидался *bridge.Error, получено %T: %v", err, err)
	}
	return be.Kind
}

func setup(t *testing.T) {
	t.Helper()
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if err := SetAssetDir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := Stop(); err != nil {
			t.Error(err)
		}
	})
}

func TestVersionIsPinnedCore(t *testing.T) {
	if v := Version(); v != "26.9.30" {
		t.Fatalf("в мост вкомпилирован Xray %s, а закреплён 26.9.30 (D-24)", v)
	}
}

func TestValidateAcceptsAndRejects(t *testing.T) {
	setup(t)
	full, err := Validate(cfg(tunIn))
	if err != nil || !full {
		t.Fatalf("корректная конфигурация: full=%v err=%v", full, err)
	}
	if _, err := Validate([]byte(`{"outbounds": [`)); kindOf(t, err) != KindConfig {
		t.Fatalf("битый JSON — KindConfig, получено %v", err)
	}
	if _, err := Validate(nil); kindOf(t, err) != KindConfig {
		t.Fatalf("пустая конфигурация — KindConfig, получено %v", err)
	}
}

func TestPolicyAllowsOnlyTunInbound(t *testing.T) {
	setup(t)
	cases := map[string][]byte{
		"socks":        cfg(`{"tag": "s", "protocol": "socks", "listen": "127.0.0.1", "port": 10808}`),
		"второй TUN":   cfg(tunIn + `,{"tag": "tun-2", "protocol": "tun", "settings": {"mtu": 1500}}`),
		"API ядра":     cfg("", `"api": {"tag": "api", "services": ["StatsService"]}`),
		"метрики HTTP": cfg("", `"metrics": {"tag": "m", "listen": "127.0.0.1:11111"}`),
		"регистр":      []byte(`{"Inbounds": [{"tag": "s", "protocol": "socks", "port": 10808}], "outbounds": [{"protocol": "freedom"}]}`),
	}
	for name, c := range cases {
		// Отвергнуть должна именно политика моста, а не сборка конфигурации.
		_, err := Validate(c)
		if err == nil || kindOf(t, err) != KindConfig || !strings.Contains(err.Error(), "мост:") {
			t.Errorf("%s: политика должна отвергнуть конфигурацию, получено %v", name, err)
		}
	}
}

// D-51: вход раздачи — только SOCKS с паролем, на частном IPv4 и с тегом раздачи.
func TestPolicyAllowsOnlyAuthenticatedShareInbound(t *testing.T) {
	setup(t)
	share := func(tag, proto, listen string, port int, settings string) string {
		return fmt.Sprintf(`{"tag": %q, "protocol": %q, "listen": %q, "port": %d, "settings": %s}`, tag, proto, listen, port, settings)
	}
	auth := `{"auth": "password", "accounts": [{"user": "u", "pass": "p-0123456789"}], "udp": true}`
	ok := cfg(tunIn + "," + share("dppass:share-0", "socks", "192.168.43.1", 41234, auth) + "," +
		share("dppass:share-1", "socks", "192.168.42.129", 41234, auth))
	if full, err := Validate(ok); err != nil || !full {
		t.Fatalf("раздача с паролем на адресах модема должна проходить: full=%v err=%v", full, err)
	}
	bad := map[string][]byte{
		"без пароля":      cfg(tunIn + "," + share("dppass:share-0", "socks", "192.168.43.1", 41234, `{"auth": "noauth"}`)),
		"все интерфейсы":  cfg(tunIn + "," + share("dppass:share-0", "socks", "0.0.0.0", 41234, auth)),
		"loopback":        cfg(tunIn + "," + share("dppass:share-0", "socks", "127.0.0.1", 41234, auth)),
		"публичный адрес": cfg(tunIn + "," + share("dppass:share-0", "socks", "203.0.113.1", 41234, auth)),
		"IPv6":            cfg(tunIn + "," + share("dppass:share-0", "socks", "fd00::1", 41234, auth)),
		"порт ниже 1024":  cfg(tunIn + "," + share("dppass:share-0", "socks", "192.168.43.1", 80, auth)),
		"чужой тег":       cfg(tunIn + "," + share("s", "socks", "192.168.43.1", 41234, auth)),
		"HTTP-вход":       cfg(tunIn + "," + share("dppass:share-0", "http", "192.168.43.1", 41234, `{"accounts": [{"user": "u", "pass": "p"}]}`)),
		"диапазон портов": cfg(tunIn + `,{"tag": "dppass:share-0", "protocol": "socks", "listen": "192.168.43.1", "port": "40000-40010", "settings": ` + auth + `}`),
	}
	for name, c := range bad {
		_, err := Validate(c)
		if err == nil || kindOf(t, err) != KindConfig || !strings.Contains(err.Error(), "мост:") {
			t.Errorf("%s: политика должна отвергнуть вход раздачи, получено %v", name, err)
		}
	}
}

// D-95: локальный прокси — только SOCKS с паролем на 127.0.0.1, со своим тегом и без TUN.
func TestPolicyAllowsOnlyAuthenticatedLoopbackProxyWithoutTun(t *testing.T) {
	setup(t)
	local := func(tag, listen string, port int, settings string) string {
		return fmt.Sprintf(`{"tag": %q, "protocol": "socks", "listen": %q, "port": %d, "settings": %s}`, tag, listen, port, settings)
	}
	auth := `{"auth": "password", "accounts": [{"user": "u", "pass": "p-0123456789"}], "udp": true, "ip": "127.0.0.1"}`
	if full, err := Validate(cfg(local("dppass:local", "127.0.0.1", 41235, auth))); err != nil || !full {
		t.Fatalf("локальный прокси с паролем на 127.0.0.1 должен проходить: full=%v err=%v", full, err)
	}
	bad := map[string][]byte{
		"без пароля":      cfg(local("dppass:local", "127.0.0.1", 41235, `{"auth": "noauth"}`)),
		"все интерфейсы":  cfg(local("dppass:local", "0.0.0.0", 41235, auth)),
		"адрес сети":      cfg(local("dppass:local", "192.168.1.5", 41235, auth)),
		"IPv6 loopback":   cfg(local("dppass:local", "::1", 41235, auth)),
		"без адреса":      cfg(`{"tag": "dppass:local", "protocol": "socks", "port": 41235, "settings": ` + auth + `}`),
		"порт ниже 1024":  cfg(local("dppass:local", "127.0.0.1", 980, auth)),
		"вместе с TUN":    cfg(tunIn + "," + local("dppass:local", "127.0.0.1", 41235, auth)),
		"чужой тег":       cfg(local("s", "127.0.0.1", 41235, auth)),
		"два прокси":      cfg(local("dppass:local", "127.0.0.1", 41235, auth) + "," + local("dppass:local", "127.0.0.1", 41236, auth)),
		"пустой пароль":   cfg(local("dppass:local", "127.0.0.1", 41235, `{"auth": "password", "accounts": [{"user": "u", "pass": ""}]}`)),
		"диапазон портов": cfg(`{"tag": "dppass:local", "protocol": "socks", "listen": "127.0.0.1", "port": "40000-40010", "settings": ` + auth + `}`),
	}
	for name, c := range bad {
		_, err := Validate(c)
		if err == nil || kindOf(t, err) != KindConfig || !strings.Contains(err.Error(), "мост:") {
			t.Errorf("%s: политика должна отвергнуть локальный прокси, получено %v", name, err)
		}
	}
}

func TestStartContract(t *testing.T) {
	setup(t)
	p := &recorder{allow: true}
	cases := []struct {
		name   string
		config []byte
		tun    Tun
		p      Protector
	}{
		{"вход TUN без fd", cfg(tunIn), NoTun, p},
		{"fd без входа TUN", cfg(""), Tun{FD: 1000, MTU: 1500}, p},
		{"MTU не совпал", cfg(tunIn), Tun{FD: 1000, MTU: 1400}, p},
		{"TUN без защитника", cfg(tunIn), Tun{FD: 1000, MTU: 1500}, nil},
	}
	for _, c := range cases {
		if err := Start(c.config, c.tun, c.p); err == nil || kindOf(t, err) != KindContract {
			t.Errorf("%s: ожидался KindContract, получено %v", c.name, err)
		}
		if Running() {
			t.Fatalf("%s: ядро запустилось вопреки договору", c.name)
		}
	}
}

func TestStartRequiresProxyCounters(t *testing.T) {
	setup(t)
	noStats := []byte(`{"log": {"loglevel": "none"}, "outbounds": [{"tag": "proxy", "protocol": "freedom"}]}`)
	if err := Start(noStats, NoTun, nil); err == nil || kindOf(t, err) != KindConfig {
		t.Fatalf("без счётчиков TrafficStats были бы нулями-неправдой: ожидался KindConfig, получено %v", err)
	}
	if Running() {
		t.Fatal("ядро запустилось без счётчиков")
	}
}

func TestSingleInstanceAndPartialValidation(t *testing.T) {
	setup(t)
	if _, _, ok := Traffic(); ok {
		t.Fatal("счётчики без ядра")
	}
	if err := Start(cfg(""), NoTun, nil); err != nil {
		t.Fatal(err)
	}
	if err := Start(cfg(""), NoTun, nil); err == nil || kindOf(t, err) != KindRunning {
		t.Fatalf("второй запуск — KindRunning, получено %v", err)
	}
	full, err := Validate(cfg(tunIn))
	if err != nil || full {
		t.Fatalf("при работающем ядре проверка неполная и без ошибки: full=%v err=%v", full, err)
	}
	if _, err := Validate([]byte(`{"inbounds": [{"protocol": "socks", "port": 1}]}`)); err == nil {
		t.Fatal("неполная проверка всё равно применяет политику входов")
	}
	if err := SetAssetDir(t.TempDir()); err == nil || kindOf(t, err) != KindRunning {
		t.Fatalf("каталог геоданных у запущенного ядра не меняется, получено %v", err)
	}
	up, down, ok := Traffic()
	if !ok || up != 0 || down != 0 {
		t.Fatalf("счётчики только что запущенного ядра: %d %d %v", up, down, ok)
	}
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if err := Stop(); err != nil {
		t.Fatalf("повторная остановка — не ошибка: %v", err)
	}
	if Running() {
		t.Fatal("ядро не остановилось")
	}
	full, err = Validate(cfg(tunIn))
	if err != nil || !full {
		t.Fatalf("после остановки проверка снова полная: full=%v err=%v", full, err)
	}
}

// recorder — защитник для тестов: запоминает fd, отвечает allow.
type recorder struct {
	allow bool
	fds   chan int
}

func (r *recorder) Protect(fd int) bool {
	if r.fds != nil {
		select {
		case r.fds <- fd:
		default:
		}
	}
	return r.allow
}
