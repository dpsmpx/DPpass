//go:build linux

package bridge

import (
	"crypto/x509"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// Проба DNS через proxy работающего ядра (D-32). Исходящий proxy в тестах
// — freedom: «сервер профиля» здесь сама ОС хоста, а серверы DNS — на
// loopback. Проверяется договор пробы: путь — через proxy и защитника, в
// обход правил; сертификат DoH проверяется; исходы различаются.

// answerTo — ответ DNS на запрос q: тот же id и вопрос, флаг QR.
func answerTo(q []byte) []byte {
	a := append([]byte(nil), q...)
	a[2] |= 0x80
	return a
}

func udpDNS(t *testing.T, reply func(q []byte) []byte) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if a := reply(buf[:n]); a != nil {
				_, _ = pc.WriteTo(a, from)
			}
		}
	}()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func tcpDNS(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				var n uint16
				if binary.Read(c, binary.BigEndian, &n) != nil {
					return
				}
				q := make([]byte, n)
				if _, err := io.ReadFull(c, q); err != nil {
					return
				}
				a := answerTo(q)
				_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
			}()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// doh — сервер DoH на loopback с самоподписанным сертификатом; корни — его.
func doh(t *testing.T, status int) (string, *x509.CertPool) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q, _ := io.ReadAll(r.Body)
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/dns-message" || len(q) < 12 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Type", "application/dns-message")
		_, _ = w.Write(answerTo(q))
	}))
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return s.URL + "/dns-query", roots
}

func withRoots(t *testing.T, roots *x509.CertPool) {
	t.Helper()
	probeRoots = roots
	t.Cleanup(func() { probeRoots = nil })
}

// startProxy — ядро без входов; правило отправляет loopback в block:
// проба обязана пройти через proxy мимо правил.
func startProxy(t *testing.T) *recorder {
	t.Helper()
	setup(t)
	p := &recorder{allow: true, fds: make(chan int, 16)}
	rules := `"routing": {"rules": [{"ip": ["127.0.0.0/8"], "outboundTag": "block"}]}`
	if err := Start(cfg("", rules), NoTun, p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProbeGoesThroughProxyPastRules(t *testing.T) {
	cases := map[string]func(t *testing.T) string{
		"udp": func(t *testing.T) string { return "udp://127.0.0.1:" + strconv.Itoa(udpDNS(t, answerTo)) },
		"tcp": func(t *testing.T) string { return "tcp://127.0.0.1:" + strconv.Itoa(tcpDNS(t)) },
		"doh": func(t *testing.T) string {
			u, roots := doh(t, http.StatusOK)
			withRoots(t, roots)
			return u
		},
	}
	for name, target := range cases {
		t.Run(name, func(t *testing.T) {
			p := startProxy(t)
			r := ProbeDNS(target(t), 5*time.Second)
			if r.Outcome != ProbeOK || r.Received == 0 {
				t.Fatalf("проба через proxy: %v", r)
			}
			select {
			case <-p.fds:
			default:
				t.Fatal("сокет пробы прошёл мимо защитника")
			}
		})
	}
}

// T5: сертификат сервера DoH проверяется всегда — чужой корень, отказ TLS.
func TestProbeVerifiesDoHCertificate(t *testing.T) {
	u, _ := doh(t, http.StatusOK)
	startProxy(t)
	if r := ProbeDNS(u, 5*time.Second); r.Outcome != ProbeTLS {
		t.Fatalf("самоподписанный сертификат без своего корня: ожидался ProbeTLS, получено %v", r)
	}
}

func TestProbeTellsBadAnswerFromSilence(t *testing.T) {
	startProxy(t)
	wrongID := udpDNS(t, func(q []byte) []byte {
		a := answerTo(q)
		a[0] ^= 0xff
		return a
	})
	if r := ProbeDNS("udp://127.0.0.1:"+strconv.Itoa(wrongID), 3*time.Second); r.Outcome != ProbeBadAnswer {
		t.Errorf("ответ с чужим id: ожидался ProbeBadAnswer, получено %v", r)
	}
	u, roots := doh(t, http.StatusForbidden)
	withRoots(t, roots)
	if r := ProbeDNS(u, 3*time.Second); r.Outcome != ProbeBadAnswer {
		t.Errorf("DoH ответил 403: ожидался ProbeBadAnswer, получено %v", r)
	}
	silent := udpDNS(t, func([]byte) []byte { return nil })
	if r := ProbeDNS("udp://127.0.0.1:"+strconv.Itoa(silent), 500*time.Millisecond); r.Outcome != ProbeUnreachable {
		t.Errorf("сервер молчит, ни байта: ожидался ProbeUnreachable, получено %v", r)
	}
	closed := freeTCPPort(t)
	if r := ProbeDNS("tcp://127.0.0.1:"+strconv.Itoa(closed), 3*time.Second); r.Outcome != ProbeUnreachable {
		t.Errorf("порт закрыт: ожидался ProbeUnreachable, получено %v", r)
	}
}

// Рукопожатие TLS прошло, ответа HTTP нет — данные не идут (L7).
func TestProbeStallsAfterHandshake(t *testing.T) {
	// Обработчик молчит дольше срока пробы. Закрытие соединения клиентом
	// ядро передаёт серверу не сразу, поэтому ожидание ограничено.
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(1500 * time.Millisecond):
		}
	}))
	s.StartTLS()
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	withRoots(t, roots)
	startProxy(t)
	r := ProbeDNS(s.URL+"/dns-query", 700*time.Millisecond)
	if r.Outcome != ProbeStalled || r.Received == 0 {
		t.Fatalf("ответа после рукопожатия нет: ожидался ProbeStalled с принятыми байтами, получено %v", r)
	}
}

func TestProbeContract(t *testing.T) {
	setup(t)
	if r := ProbeDNS("udp://127.0.0.1:53", time.Second); r.Outcome != ProbeNotRunning {
		t.Errorf("ядро не запущено: ожидался ProbeNotRunning, получено %v", r)
	}
	startProxy(t)
	for _, bad := range []string{"", "dns://127.0.0.1", "udp://", "https://127.0.0.1:99999/x"} {
		if r := ProbeDNS(bad, time.Second); r.Outcome != ProbeContract {
			t.Errorf("цель %q: ожидался отказ договора, получено %v", bad, r)
		}
	}
	if r := ProbeDNS("udp://127.0.0.1:53", 0); r.Outcome != ProbeContract {
		t.Errorf("нулевой срок: ожидался ProbeContract, получено %v", r)
	}
}

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}
