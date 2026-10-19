//go:build linux && dppass_testinbound

package bridge

import (
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

// Разбиение ClientHello к серверу (D-68) в работающем ядре: исходящий
// proxy (trojan с TLS) открывает соединение с «сервером» через выход
// freedom с fragment (`sockopt.dialerProxy`), как пишет компилятор DPpass.
// «Сервер» на loopback только записывает, что пришло: рукопожатие не
// доходит до конца, проверяется сам ClientHello.

type arrival struct {
	data  []byte
	reads int
}

// helloServer принимает одно соединение и копит первые байты, пока
// не придёт весь ClientHello (по длине в заголовке сообщения рукопожатия).
func helloServer(t *testing.T) (port int, got chan arrival) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	got = make(chan arrival, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(5 * time.Second))
		var a arrival
		buf := make([]byte, 4096)
		for !complete(a.data) {
			n, err := c.Read(buf)
			if n > 0 {
				a.data = append(a.data, buf[:n]...)
				a.reads++
			}
			if err != nil {
				break
			}
		}
		got <- a
	}()
	return l.Addr().(*net.TCPAddr).Port, got
}

// records — длины записей TLS типа «рукопожатие» (22) подряд с начала.
func records(b []byte) []int {
	var out []int
	for len(b) >= 5 && b[0] == 22 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			break
		}
		out = append(out, n)
		b = b[5+n:]
	}
	return out
}

// complete — пришёл ли весь ClientHello: сумма записей покрывает
// сообщение рукопожатия (тип 1, длина — 3 байта после типа).
func complete(b []byte) bool {
	var body []byte
	for len(b) >= 5 && b[0] == 22 {
		n := int(b[3])<<8 | int(b[4])
		if len(b) < 5+n {
			return false
		}
		body = append(body, b[5:5+n]...)
		b = b[5+n:]
	}
	return len(body) >= 4 && len(body) >= 4+(int(body[1])<<16|int(body[2])<<8|int(body[3]))
}

func splitCfg(in, server int, split bool) []byte {
	sockopt, extra := "", ""
	if split {
		sockopt = `, "sockopt": {"dialerProxy": "dppass:split"}`
		extra = `, {"tag": "dppass:split", "protocol": "freedom",
			"settings": {"fragment": {"packets": "tlshello", "length": "40-80", "interval": "1-3"}}}`
	}
	return []byte(fmt.Sprintf(`{"log": {"loglevel": "none"}, "stats": {},
		"policy": {"system": {"statsOutboundUplink": true, "statsOutboundDownlink": true}},
		"inbounds": [%s],
		"outbounds": [{"tag": "proxy", "protocol": "trojan",
			"settings": {"address": "127.0.0.1", "port": %d, "password": "synthetic-password"},
			"streamSettings": {"network": "raw", "security": "tls", "tlsSettings": {"serverName": "www.example.com"}%s}}%s]}`,
		testInbound(in, 9), server, sockopt, extra))
}

func helloThroughCore(t *testing.T, split bool) (arrival, *recorder) {
	t.Helper()
	setup(t)
	server, got := helloServer(t)
	in := freePort(t)
	p := &recorder{allow: true, fds: make(chan int, 16)}
	if err := Start(splitCfg(in, server, split), NoTun, p); err != nil {
		t.Fatal(err)
	}
	c := dialCore(t, in)
	defer c.Close()
	_, _ = c.Write([]byte("dppass"))
	select {
	case a := <-got:
		return a, p
	case <-time.After(5 * time.Second):
		t.Fatal("ClientHello не дошёл до сервера")
	}
	return arrival{}, p
}

func TestClientHelloGoesInPiecesThroughSplitDialer(t *testing.T) {
	whole, _ := helloThroughCore(t, false)
	if r := records(whole.data); len(r) != 1 || !complete(whole.data) {
		t.Fatalf("без разбиения ClientHello — одна запись TLS, пришло %v", r)
	}

	a, p := helloThroughCore(t, true)
	r := records(a.data)
	if !complete(a.data) {
		t.Fatalf("с разбиением ClientHello пришёл не целиком: записи %v", r)
	}
	if len(r) < 3 {
		t.Fatalf("с разбиением ClientHello — несколько записей TLS, пришло %v", r)
	}
	for _, n := range r[:len(r)-1] {
		if n < 40 || n > 80 {
			t.Fatalf("часть %d байт вне 40–80: %v", n, r)
		}
	}
	t.Logf("ClientHello %d байт: без разбиения — 1 запись; с разбиением — %d записей, %d чтений", records(whole.data)[0], len(r), a.reads)
	// Каждая запись — отдельной записью в сокет с паузой: на loopback это
	// отдельные чтения (отдельные сегменты TCP), а не один кусок.
	if a.reads < 2 {
		t.Fatalf("записи TLS пришли одним куском (%d чтение) — сегментов нет", a.reads)
	}
	select {
	case <-p.fds:
	default:
		t.Fatal("сокет выхода разбиения прошёл мимо защитника")
	}
	if strings.Contains(string(a.data), "synthetic-password") {
		t.Fatal("пароль trojan ушёл до рукопожатия TLS")
	}
}
