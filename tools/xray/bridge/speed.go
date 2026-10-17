//go:build linux

package bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
)

// Замер через туннель по кнопке (D-61): пинг, jitter и скорость загрузки
// через исходящий proxy работающего ядра — то, что получает приложение в
// туннеле. Одно TLS-соединение: сначала [SpeedTest.pings] малых запросов
// по очереди, затем одна загрузка не больше maxBytes и не дольше maxTime.
// Адрес — https://хост[:порт]/путь; малый запрос — путь?bytes=0, загрузка —
// путь?bytes=N (адрес с заданным объёмом ответа, D-60).

// SpeedResult — время ответа на каждый малый запрос, сколько байт тела
// загрузки пришло и за какое время. Исход — как у пробы DNS.
type SpeedResult struct {
	Outcome  ProbeOutcome
	Pings    []time.Duration
	Received int64
	Transfer time.Duration
	Err      error
}

// SpeedTest — замер через proxy ядра; timeout — на весь замер.
func SpeedTest(target string, pings int, maxBytes int64, maxTime, timeout time.Duration) SpeedResult {
	mu.Lock()
	inst := current
	mu.Unlock()
	if inst == nil {
		return SpeedResult{Outcome: ProbeNotRunning, Err: errors.New("ядро не запущено")}
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "https" || pings < 1 || pings > 50 || maxBytes < 1 || maxTime <= 0 || timeout <= maxTime {
		return SpeedResult{Outcome: ProbeContract, Err: fmt.Errorf("замер %q (%d, %d, %v, %v) не понят", target, pings, maxBytes, maxTime, timeout)}
	}
	host, port, err := hostPort(u, 443)
	if err != nil {
		return SpeedResult{Outcome: ProbeContract, Err: err}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	tracked := &outboundError{}
	ctx = session.TrackedConnectionError(ctx, tracked)
	c := &countingConn{}
	res := SpeedResult{}
	err = speed(ctx, inst, u, host, port, pings, maxBytes, maxTime, c, &res)
	res.Outcome = classify(err, ctx.Err() != nil, c.received.Load())
	if oe := tracked.get(); err != nil && oe != nil {
		err = &outboundFailure{err: err, outbound: oe}
	}
	res.Err = err
	return res
}

func speed(ctx context.Context, inst *core.Instance, u *url.URL, host string, port, pings int, maxBytes int64, maxTime time.Duration, c *countingConn, res *SpeedResult) error {
	raw, err := dial(ctx, inst, xnet.Network_TCP, host, port, c)
	if err != nil {
		return err
	}
	defer raw.Close()
	tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: probeRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		return &stageError{outcome: ProbeTLS, err: err}
	}
	br := bufio.NewReader(tc)
	for i := 0; i < pings; i++ {
		start := time.Now()
		resp, err := request(ctx, tc, br, u, 0, false)
		if err != nil {
			return err
		}
		res.Pings = append(res.Pings, time.Since(start))
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
		_ = resp.Body.Close()
	}
	resp, err := request(ctx, tc, br, u, maxBytes, true)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Срок загрузки — по таймеру: чтение соединения ядра о сроках не знает.
	var expired atomic.Bool
	timer := time.AfterFunc(maxTime, func() {
		expired.Store(true)
		_ = raw.Close()
	})
	defer timer.Stop()
	start := time.Now()
	n, err := io.Copy(io.Discard, io.LimitReader(resp.Body, maxBytes))
	res.Received = n
	res.Transfer = time.Since(start)
	switch {
	case err == nil, expired.Load() && n > 0:
		// Срок загрузки вышел посреди тела — замер состоялся: столько пришло за maxTime.
		return nil
	case expired.Load():
		return &stageError{outcome: ProbeStalled, err: fmt.Errorf("за %v не пришло ни байта тела загрузки", maxTime)}
	}
	return err
}

// request — GET путь?bytes=n по уже открытому соединению; last — последний
// запрос, сервер может закрыть соединение. Код ответа — только 200.
func request(ctx context.Context, tc *tls.Conn, br *bufio.Reader, u *url.URL, n int64, last bool) (*http.Response, error) {
	q := *u
	values := q.Query()
	values.Set("bytes", strconv.FormatInt(n, 10))
	q.RawQuery = values.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, q.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "DPpass")
	req.Close = last
	if err := req.Write(tc); err != nil {
		return nil, err
	}
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, badAnswer("замер: сервер ответил HTTP %d", resp.StatusCode)
	}
	return resp, nil
}
