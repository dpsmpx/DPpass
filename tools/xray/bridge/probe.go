//go:build linux

package bridge

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

// Проверка здоровья по полезной нагрузке (D-15, D-32): один запрос DNS к
// серверу DnsPolicy через исходящий proxy работающего ядра — в обход
// правил маршрутизации. Ответ сервера DNS пришёл — данные прошли через
// сервер профиля туда и обратно. Сервер DNS — из конфигурации
// пользователя: новых связей со сторонними серверами проверка не
// создаёт (D-12).
//
// Спрашивается «. NS»: корневые серверы знает любой рекурсивный резолвер,
// а сам запрос ничего не говорит о пользователе.

// ProbeOutcome — исход пробы. Числа — договор с engine.xray.DnsProbeOutcome (Kotlin).
type ProbeOutcome uint8

const (
	// ProbeOK — пришёл ответ DNS на наш запрос.
	ProbeOK ProbeOutcome = 0
	// ProbeUnreachable — соединение через сервер профиля закрылось, не
	// передав ни байта: сервер недоступен или отверг соединение.
	ProbeUnreachable ProbeOutcome = 1
	// ProbeTLS — TLS с сервером DoH не установлен: сертификат не прошёл
	// проверку или рукопожатие отвергнуто.
	ProbeTLS ProbeOutcome = 2
	// ProbeStalled — за отведённое время ответа нет: соединение есть,
	// данные не идут (L7).
	ProbeStalled ProbeOutcome = 3
	// ProbeBadAnswer — байты пришли, но это не ответ DNS на наш запрос
	// (код HTTP не 200, чужой id, обрезанное сообщение).
	ProbeBadAnswer ProbeOutcome = 4
	// ProbeNotRunning — ядро не запущено.
	ProbeNotRunning ProbeOutcome = 5
	// ProbeContract — цель пробы не понята (договор вызова).
	ProbeContract ProbeOutcome = 6
)

// proxyTag — исходящий профиля в конфигурации компилятора DPpass (XrayBackend.TAG_PROXY).
const proxyTag = "proxy"

// maxDNSMessage — предел ответа: больше DNS-сообщение не бывает (RFC 1035, 4.2.2).
const maxDNSMessage = 65535

// probeRoots — корневые сертификаты для DoH; nil — системные (на Android —
// /system/etc/security/cacerts). Меняют только тесты моста: проверка
// сертификата не выключается никогда (T5).
var probeRoots *x509.CertPool

// ProbeResult — исход, время до ответа и сколько байт пришло через сервер.
type ProbeResult struct {
	Outcome  ProbeOutcome
	Elapsed  time.Duration
	Received int64
	Err      error
}

// ProbeDNS — запрос «. NS» к target через proxy работающего ядра.
// target — https://хост[:порт]/путь (DoH), udp://хост:порт или tcp://хост:порт.
func ProbeDNS(target string, timeout time.Duration) ProbeResult {
	mu.Lock()
	inst := current
	mu.Unlock()
	if inst == nil {
		return ProbeResult{Outcome: ProbeNotRunning, Err: errors.New("ядро не запущено")}
	}
	u, err := url.Parse(target)
	if err != nil || timeout <= 0 {
		return ProbeResult{Outcome: ProbeContract, Err: fmt.Errorf("цель пробы %q или время %v не поняты", target, timeout)}
	}
	defaults := map[string]int{"https": 443, "udp": 53, "tcp": 53}
	def, known := defaults[u.Scheme]
	if !known {
		return ProbeResult{Outcome: ProbeContract, Err: fmt.Errorf("схема %q — ожидалась https, udp или tcp", u.Scheme)}
	}
	host, port, err := hostPort(u, def)
	if err != nil {
		return ProbeResult{Outcome: ProbeContract, Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	start := time.Now()
	c := &countingConn{}
	var answer []byte
	query, id := dnsQuery()
	if u.Scheme == "https" {
		answer, err = probeDoH(ctx, inst, u, host, port, query, c)
	} else {
		answer, err = probePlain(ctx, inst, u.Scheme, host, port, query, c)
	}
	res := ProbeResult{Elapsed: time.Since(start), Received: c.received.Load()}
	if err == nil {
		err = checkAnswer(answer, id)
	}
	res.Outcome, res.Err = classify(err, ctx.Err() != nil, res.Received), err
	return res
}

// classify — исход по ошибке, истёкшему сроку и числу пришедших байт.
// Ни байта через сервер профиля — недоступен, на каком бы этапе ни
// оборвалось; иначе срок — данные не идут, отказ TLS — TLS, остальное —
// ответ не тот.
func classify(err error, expired bool, received int64) ProbeOutcome {
	var stage *stageError
	var bad *answerError
	switch {
	case err == nil:
		return ProbeOK
	case received == 0:
		return ProbeUnreachable
	case expired:
		return ProbeStalled
	case errors.As(err, &bad):
		return ProbeBadAnswer
	case errors.As(err, &stage):
		return stage.outcome
	}
	return ProbeBadAnswer
}

// stageError — отказ этапа, у которого свой исход (рукопожатие TLS).
type stageError struct {
	outcome ProbeOutcome
	err     error
}

func (e *stageError) Error() string { return e.err.Error() }
func (e *stageError) Unwrap() error { return e.err }

// answerError — ответ пришёл, но не тот.
type answerError struct{ msg string }

func (e *answerError) Error() string { return e.msg }

func badAnswer(format string, args ...any) error {
	return &answerError{msg: fmt.Sprintf(format, args...)}
}

// dial — соединение с хостом через proxy ядра: правила маршрутизации не
// применяются (иначе правило direct увело бы пробу мимо сервера профиля).
// Имя хоста резолвит сервер профиля, а не устройство.
func dial(ctx context.Context, inst *core.Instance, network xnet.Network, host string, port int, c *countingConn) (net.Conn, error) {
	addr := xnet.ParseAddress(host)
	dest := xnet.Destination{Network: network, Address: addr, Port: xnet.Port(port)}
	pctx := session.SetForcedOutboundTagToContext(ctx, proxyTag)
	conn, err := core.Dial(pctx, inst, dest)
	if err != nil {
		return nil, err
	}
	c.Conn = conn
	// Чтение соединения ядра не знает о сроке: по сроку оно закрывается.
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	return c, nil
}

func hostPort(u *url.URL, def int) (string, int, error) {
	if u.Hostname() == "" {
		return "", 0, fmt.Errorf("в цели пробы нет хоста")
	}
	port := def
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n <= 0 || n > 65535 {
			return "", 0, fmt.Errorf("порт %q", p)
		}
		port = n
	}
	return u.Hostname(), port, nil
}

func probeDoH(ctx context.Context, inst *core.Instance, u *url.URL, host string, port int, query []byte, c *countingConn) ([]byte, error) {
	raw, err := dial(ctx, inst, xnet.Network_TCP, host, port, c)
	if err != nil {
		return nil, err
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: probeRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return nil, &stageError{outcome: ProbeTLS, err: err}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.String(), bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Close = true
	if err := req.Write(tc); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(tc), req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, badAnswer("сервер DoH ответил HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDNSMessage+1))
	if err != nil {
		return nil, err
	}
	return body, nil
}

func probePlain(ctx context.Context, inst *core.Instance, scheme, host string, port int, query []byte, c *countingConn) ([]byte, error) {
	network := xnet.Network_UDP
	if scheme == "tcp" {
		network = xnet.Network_TCP
	}
	conn, err := dial(ctx, inst, network, host, port, c)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if network == xnet.Network_UDP {
		if _, err := conn.Write(query); err != nil {
			return nil, err
		}
		buf := make([]byte, maxDNSMessage)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		return buf[:n], nil
	}
	// DNS по TCP: сообщение с длиной в два байта (RFC 1035, 4.2.2).
	framed := binary.BigEndian.AppendUint16(nil, uint16(len(query)))
	if _, err := conn.Write(append(framed, query...)); err != nil {
		return nil, err
	}
	var n uint16
	if err := binary.Read(conn, binary.BigEndian, &n); err != nil {
		return nil, err
	}
	msg := make([]byte, n)
	if _, err := io.ReadFull(conn, msg); err != nil {
		return nil, err
	}
	return msg, nil
}

// dnsQuery — «. IN NS» со случайным id и флагом RD.
func dnsQuery() ([]byte, uint16) {
	var b [2]byte
	_, _ = rand.Read(b[:])
	id := binary.BigEndian.Uint16(b[:])
	q := binary.BigEndian.AppendUint16(nil, id)
	q = append(q, 0x01, 0x00) // RD
	q = append(q, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, 0)          // корень
	q = append(q, 0, 2, 0, 1) // NS, IN
	return q, id
}

// checkAnswer — ответ на наш запрос: тот же id, флаг QR, тот же вопрос.
// Код ответа не важен: даже отказ (REFUSED) пришёл через сервер профиля.
func checkAnswer(m []byte, id uint16) error {
	switch {
	case len(m) > maxDNSMessage:
		return badAnswer("ответ длиннее DNS-сообщения")
	case len(m) < 17:
		return badAnswer("ответ короче заголовка и вопроса DNS (%d байт)", len(m))
	case binary.BigEndian.Uint16(m[0:2]) != id:
		return badAnswer("ответ DNS с чужим id")
	case m[2]&0x80 == 0:
		return badAnswer("пришёл не ответ DNS (нет флага QR)")
	case binary.BigEndian.Uint16(m[4:6]) != 1 || !bytes.Equal(m[12:17], []byte{0, 0, 2, 0, 1}):
		return badAnswer("ответ DNS не на наш вопрос")
	}
	return nil
}

// countingConn считает байты, пришедшие через соединение ядра: «ни байта»
// отличает недоступный сервер от сломанного ответа.
type countingConn struct {
	net.Conn
	received atomic.Int64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.received.Add(int64(n))
	return n, err
}

// String — для журнала теста.
func (r ProbeResult) String() string {
	parts := []string{fmt.Sprintf("исход %d", r.Outcome), fmt.Sprintf("%v", r.Elapsed.Round(time.Millisecond)), fmt.Sprintf("%d байт", r.Received)}
	if r.Err != nil {
		parts = append(parts, r.Err.Error())
	}
	return strings.Join(parts, ", ")
}
