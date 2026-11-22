//go:build linux || windows

package bridge

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
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
// туннеле. Отдельное защищённое TLS-соединение для каждого из
// [SpeedTest.pings] малых запросов, затем новая загрузка до maxBytes/maxTime.
// Адрес — https://хост[:порт]/путь; малый запрос — путь?bytes=0, загрузка —
// путь?bytes=N (адрес с заданным объёмом ответа, D-60).

// SpeedResult — время ответа на каждый малый запрос, сколько байт тела
// загрузки пришло, за какое время и когда пришёл последний байт (от начала
// загрузки): последний байт задолго до конца срока — данные встали (L7), а
// не канал медленный. Исход — как у пробы DNS.
type SpeedResult struct {
	Outcome  ProbeOutcome
	Pings    []time.Duration
	Received int64
	Transfer time.Duration
	LastByte time.Duration
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
	phase := "outbound_dial"
	err = speed(ctx, inst, u, host, port, pings, maxBytes, maxTime, c, &res, &phase)
	res.Outcome = classifySpeed(err, ctx.Err() != nil, c.received.Load())
	if err != nil {
		// Do not claim that the entire network is blocked when this
		// specific HTTPS measurement failed. Log only the protocol phase,
		// number of completed small requests and measured body bytes;
		// neither URLs nor payloads enter the diagnostic.
		err = fmt.Errorf("speed_stage=%s completed_pings=%d download_bytes=%d: %w",
			phase, len(res.Pings), res.Received, err)
	}
	if oe := tracked.get(); err != nil && oe != nil {
		err = &outboundFailure{err: err, outbound: oe}
	}
	res.Err = err
	return res
}

// TLS handshake failures must not be reported as a generic stalled download
// just because the kernel returned a few TLS bytes before the deadline.
// Keep other outcomes consistent with ordinary DNS/HTTP probe classification.
func classifySpeed(err error, expired bool, received int64) ProbeOutcome {
	var stage *stageError
	if errors.As(err, &stage) && stage.outcome == ProbeTLS {
		return ProbeTLS
	}
	return classify(err, expired, received)
}

// Each latency request opens a fresh protected Xray->Zapret2 TCP/TLS
// connection. Some middleboxes/CDNs accept the first two HTTP/1.1
// keep-alive requests but silently drop subsequent responses on the same
// flow. Reusing one TLS socket made the entire 25-second measurement fail
// before the download even began, despite two successful pings. There is
// no direct-network fallback: every connection uses the Xray outbound.
func speed(ctx context.Context, inst *core.Instance, u *url.URL, host string, port, pings int, maxBytes int64, maxTime time.Duration, c *countingConn, res *SpeedResult, phase *string) error {
    for i := 0; i < pings; i++ {
        raw, tc, br, err := openSpeedTLS(ctx, inst, host, port, c, phase)
        if err != nil { return err }
        *phase = "latency_http"
        start := time.Now()
        resp, err := request(ctx, tc, br, u, 0, true)
        if err == nil {
            // Only append a successful HTTP timing. A broken body or a
            // truncated response must not be silently counted as a ping.
            _, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
            _ = resp.Body.Close()
        }
        _ = raw.Close()
        if err != nil { return err }
        res.Pings = append(res.Pings, time.Since(start))
    }

    // The bulk transfer gets its own fresh TLS flow, protected and
    // desynchronized just like each latency request.
    raw, tc, br, err := openSpeedTLS(ctx, inst, host, port, c, phase)
    if err != nil { return err }
    defer raw.Close()
    *phase = "download_headers"
    resp, err := request(ctx, tc, br, u, maxBytes, true)
    if err != nil { return err }
    defer resp.Body.Close()

    *phase = "download_body"
    // Bound download duration independently of overall ping/setup timeout.
    var expired atomic.Bool
    timer := time.AfterFunc(maxTime, func() {
        expired.Store(true)
        _ = raw.Close()
    })
    defer timer.Stop()
    start := time.Now()
    w := &lastByteWriter{start: start}
    n, err := io.Copy(w, io.LimitReader(resp.Body, maxBytes))
    res.Received = n
    res.Transfer = time.Since(start)
    res.LastByte = w.last
    switch {
    case err == nil, expired.Load() && n > 0:
        return nil
    case expired.Load():
        return &stageError{outcome: ProbeStalled, err: fmt.Errorf("за %v не пришло ни байта тела загрузки", maxTime)}
    }
    return err
}

func openSpeedTLS(ctx context.Context, inst *core.Instance, host string, port int, c *countingConn, phase *string) (net.Conn, *tls.Conn, *bufio.Reader, error) {
    *phase = "outbound_dial"
    raw, err := dial(ctx, inst, xnet.Network_TCP, host, port, c)
    if err != nil { return nil, nil, nil, err }
    *phase = "tls_handshake"
    tc := tls.Client(raw, &tls.Config{ServerName: host, RootCAs: probeRoots, NextProtos: []string{"http/1.1"}, MinVersion: tls.VersionTLS12})
    if err := tc.HandshakeContext(ctx); err != nil {
        _ = raw.Close()
        return nil, nil, nil, &stageError{outcome: ProbeTLS, err: err}
    }
    return raw, tc, bufio.NewReader(tc), nil
}

// lastByteWriter — приёмник тела загрузки: запоминает, когда пришли последние байты.
type lastByteWriter struct {
	start time.Time
	last  time.Duration
}

func (w *lastByteWriter) Write(p []byte) (int, error) {
	if len(p) > 0 {
		w.last = time.Since(w.start)
	}
	return len(p), nil
}

// request — GET путь?bytes=n по открытому TLS-соединению;
// соединение закрывается после ответа. Код ответа — только 200.
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
