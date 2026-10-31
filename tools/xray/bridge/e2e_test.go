//go:build linux && dppass_testinbound

package bridge

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

// Сквозные тесты на хосте: соединение входит в ядро через тестовый вход
// на loopback, уходит исходящим proxy (freedom) к эхо-серверу. Так
// проверяется то, ради чего мост существует: каждый исходящий сокет
// ядра проходит через защитника, а отказ защитника закрывает путь.

func echoServer(t *testing.T) (port int, accepted chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	accepted = make(chan struct{}, 16)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			accepted <- struct{}{}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port, accepted
}

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func testInbound(port, target int) string {
	return fmt.Sprintf(`{"tag": "test-in", "protocol": "dokodemo-door", "listen": "127.0.0.1", "port": %d,
		"settings": {"address": "127.0.0.1", "port": %d, "network": "tcp"}}`, port, target)
}

// dialCore — соединение с ядром через тестовый вход: вход может открыться
// не мгновенно после Start, поэтому несколько попыток.
func dialCore(t *testing.T, port int) net.Conn {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err == nil {
			_ = c.SetDeadline(time.Now().Add(5 * time.Second))
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("тестовый вход ядра не принимает соединения: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestProtectorSeesCoreSocketsAndDataFlows(t *testing.T) {
	setup(t)
	echo, accepted := echoServer(t)
	in := freePort(t)
	p := &recorder{allow: true, fds: make(chan int, 16)}
	if err := Start(cfg(testInbound(in, echo)), NoTun, p); err != nil {
		t.Fatal(err)
	}
	c := dialCore(t, in)
	msg := bytes.Repeat([]byte("dppass-bridge-"), 64)
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, len(msg))
	if _, err := io.ReadFull(c, got); err != nil {
		t.Fatalf("эхо через ядро: %v", err)
	}
	if !bytes.Equal(got, msg) {
		t.Fatal("эхо через ядро вернуло другие байты")
	}
	select {
	case fd := <-p.fds:
		if fd < 0 {
			t.Fatalf("защитник получил fd %d", fd)
		}
	default:
		t.Fatal("исходящий сокет ядра прошёл мимо защитника")
	}
	<-accepted
	// Счётчики proxy: на хосте freedom сращивает два сокета TCP (splice), и
	// переданное через ядро ОС добавляется к счётчику, когда соединение
	// закрыто; с входом TUN сращивания нет. Поэтому — после закрытия и с пределом.
	_ = c.Close()
	deadline := time.Now().Add(5 * time.Second)
	for {
		up, down, ok := Traffic()
		if ok && up >= int64(len(msg)) && down >= int64(len(msg)) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("счётчики proxy: вверх %d, вниз %d, ожидалось ≥ %d", up, down, len(msg))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestRefusedProtectionClosesThePath(t *testing.T) {
	setup(t)
	echo, accepted := echoServer(t)
	in := freePort(t)
	p := &recorder{allow: false, fds: make(chan int, 16)}
	if err := Start(cfg(testInbound(in, echo)), NoTun, p); err != nil {
		t.Fatal(err)
	}
	c := dialCore(t, in)
	defer c.Close()
	_, _ = c.Write([]byte("must not arrive"))
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err == nil {
		t.Fatalf("соединение без защиты передало данные: %q", buf[:n])
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("ядро не закрыло соединение, а повисло")
	}
	select {
	case <-p.fds:
	default:
		t.Fatal("защитник не был спрошен")
	}
	select {
	case <-accepted:
		t.Fatal("незащищённый сокет ядра всё-таки соединился с сервером")
	case <-time.After(200 * time.Millisecond):
	}
}

func TestStoppedCoreReleasesInbound(t *testing.T) {
	setup(t)
	echo, _ := echoServer(t)
	in := freePort(t)
	if err := Start(cfg(testInbound(in, echo)), NoTun, nil); err != nil {
		t.Fatal(err)
	}
	dialCore(t, in).Close()
	if err := Stop(); err != nil {
		t.Fatal(err)
	}
	if c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", in), time.Second); err == nil {
		c.Close()
		t.Fatal("после Stop вход ядра всё ещё принимает соединения")
	}
}

// Даже в тестовой сборке вход допускается только на loopback.
func TestTestInboundOnlyOnLoopback(t *testing.T) {
	setup(t)
	in := strings.Replace(testInbound(freePort(t), 9), "127.0.0.1\", \"port\"", "0.0.0.0\", \"port\"", 1)
	if !strings.Contains(in, `"listen": "0.0.0.0"`) {
		t.Fatal("тест собрал не тот вход")
	}
	if _, err := Validate(cfg(in)); err == nil || !strings.Contains(err.Error(), "мост:") {
		t.Fatalf("вход на 0.0.0.0 должен быть отвергнут политикой, получено %v", err)
	}
}

// Учёт соединений (D-106) через настоящее ядро: соединение видно с
// назначением, маршрутом и итогом.
func TestConnTrackingSeesCoreConnection(t *testing.T) {
	setup(t)
	SetConnTracking(true)
	t.Cleanup(func() { SetConnTracking(false) })
	echo, _ := echoServer(t)
	in := freePort(t)
	p := &recorder{allow: true, fds: make(chan int, 16)}
	if err := Start(cfg(testInbound(in, echo)), NoTun, p); err != nil {
		t.Fatal(err)
	}
	c := dialCore(t, in)
	msg := []byte("dppass-conntrack")
	if _, err := c.Write(msg); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(c, make([]byte, len(msg))); err != nil {
		t.Fatalf("эхо через ядро: %v", err)
	}
	_ = c.Close()
	target := fmt.Sprintf("127.0.0.1:%d", echo)
	deadline := time.Now().Add(5 * time.Second)
	for {
		lines, on, _ := ConnSnapshot()
		for _, l := range lines {
			f := strings.Split(l, "\t")
			if len(f) == 17 && f[4] == target {
				if f[1] != "tcp" || f[2] != "test-in" {
					t.Fatalf("соединение учтено не так: %q", l)
				}
				// Маршрут известен к первым данным ответа или к закрытию. Байты
				// ответа здесь могут быть нулём: freedom сращивает сокеты входа
				// dokodemo (splice) мимо каналов ядра; у входа TUN сращивания нет.
				if f[8] == "c" {
					if f[7] != "proxy" || f[13] != fmt.Sprint(len(msg)) {
						t.Fatalf("закрытое учтено не так: %q", l)
					}
					return
				}
			}
		}
		if !on {
			t.Fatal("учёт выключился сам")
		}
		if time.Now().After(deadline) {
			t.Fatalf("закрытого соединения к %s в снимке нет: %v", target, lines)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
