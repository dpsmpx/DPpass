//go:build linux

package bridge

import (
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"strings"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"
	"time"
)

// Замер через туннель (D-61): тот же путь, что у пробы DNS, — через proxy
// ядра мимо правил; сервер с заданным объёмом ответа — на loopback.

// down — сервер «путь?bytes=N»: N байт; chunk и pause — медленная выдача;
// stall — после заголовков загрузки ни байта; freezeAfter > 0 — столько байт
// тела и тишина (как «заморозка» L7).
func down(t *testing.T, status int, chunk int, pause time.Duration, stall bool, freezeAfter ...int) (string, *x509.CertPool) {
	t.Helper()
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
		if r.URL.Path != "/__down" || err != nil || r.Header.Get("User-Agent") != "DPpass" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		w.WriteHeader(http.StatusOK)
		if n == 0 {
			return
		}
		w.(http.Flusher).Flush()
		if stall {
			<-r.Context().Done()
			return
		}
		if len(freezeAfter) > 0 {
			_, _ = w.Write(make([]byte, freezeAfter[0]))
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			return
		}
		buf := make([]byte, chunk)
		for sent := 0; sent < n; sent += chunk {
			if _, err := w.Write(buf[:min(chunk, n-sent)]); err != nil {
				return
			}
			if pause > 0 {
				w.(http.Flusher).Flush()
				time.Sleep(pause)
			}
		}
	}))
	t.Cleanup(s.Close)
	roots := x509.NewCertPool()
	roots.AddCert(s.Certificate())
	return s.URL + "/__down", roots
}

func TestSpeedTestPingsThenDownloadsThroughProxy(t *testing.T) {
	u, roots := down(t, http.StatusOK, 64<<10, 0, false)
	withRoots(t, roots)
	p := startProxy(t)
	r := SpeedTest(u, 5, 2<<20, 5*time.Second, 10*time.Second)
	if r.Outcome != ProbeOK || len(r.Pings) != 5 || r.Received != 2<<20 || r.Transfer <= 0 {
		t.Fatalf("замер через proxy: %+v", r)
	}
	select {
	case <-p.fds:
	default:
		t.Fatal("сокет замера прошёл мимо защитника")
	}
}

func TestSpeedTestStopsAtTimeLimit(t *testing.T) {
	u, roots := down(t, http.StatusOK, 16<<10, 20*time.Millisecond, false)
	withRoots(t, roots)
	startProxy(t)
	r := SpeedTest(u, 2, 100<<20, 400*time.Millisecond, 10*time.Second)
	if r.Outcome != ProbeOK || r.Received == 0 || r.Received >= 100<<20 || r.Transfer < 300*time.Millisecond || r.Transfer > 3*time.Second {
		t.Fatalf("по сроку: %+v", r)
	}
}

// «Заморозка» (L7): часть тела и тишина до конца срока — замер состоялся,
// но последний байт пришёл задолго до конца: это видно, а не прячется в среднем.
func TestSpeedTestSeesDataStoppingMidTransfer(t *testing.T) {
	u, roots := down(t, http.StatusOK, 1, 0, false, 200<<10)
	withRoots(t, roots)
	startProxy(t)
	r := SpeedTest(u, 2, 10<<20, 800*time.Millisecond, 10*time.Second)
	if r.Outcome != ProbeOK || r.Received != 200<<10 || r.LastByte <= 0 || r.Transfer-r.LastByte < 500*time.Millisecond {
		t.Fatalf("заморозка после 200 КБ: %+v", r)
	}
}

// A mobile network can accept TCP and even return some TLS bytes but fail
// to complete the handshake. This must not be labelled "download stalled":
// users otherwise cannot distinguish blocked TLS from stalled HTTP payload.
func TestSpeedTLSHandshakeDeadlineReportsAccurateStage(t *testing.T) {
    ln, err := net.Listen("tcp", "127.0.0.1:0")
    if err != nil { t.Fatal(err) }
    defer ln.Close()
    go func() {
        conn, err := ln.Accept()
        if err != nil { return }
        defer conn.Close()
        _, _ = io.Copy(io.Discard, conn) // accept ClientHello, never send ServerHello
    }()
    startProxy(t)
    r := SpeedTest("https://"+ln.Addr().String()+"/__down",
        2, 1024, 100*time.Millisecond, 650*time.Millisecond)
    if r.Outcome != ProbeTLS || r.Err == nil ||
        !strings.Contains(r.Err.Error(), "speed_stage=tls_handshake") ||
        !strings.Contains(r.Err.Error(), "completed_pings=0") {
        t.Fatalf("TLS handshake timeout misreported as L7 stall: %+v", r)
    }
}

// TLS may succeed while the actual HTTP measurement endpoint never sends
// response headers. The phase is safe to log and distinguishes this from
// failure to initiate TLS or from a body stalled mid-download.
func TestSpeedHTTPHeadersDeadlineReportsLatencyStage(t *testing.T) {
    s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        <-r.Context().Done() // no HTTP headers until caller cancels
    }))
    defer s.Close()
    roots := x509.NewCertPool()
    roots.AddCert(s.Certificate())
    withRoots(t, roots)
    startProxy(t)
    r := SpeedTest(s.URL+"/__down", 2, 1024,
        100*time.Millisecond, 650*time.Millisecond)
    if r.Outcome != ProbeStalled || r.Err == nil ||
        !strings.Contains(r.Err.Error(), "speed_stage=latency_http") ||
        !strings.Contains(r.Err.Error(), "completed_pings=0") {
        t.Fatalf("HTTP header stall needs a distinct phase: %+v", r)
    }
}

// The field report had two successful latency requests, then the
// third HTTP response never arrived on the persistent TLS flow. A
// middlebox or CDN can stall reused connections while accepting fresh
// handshakes. Every request must therefore use its own protected Xray
// outbound socket; silently retrying direct would be a security bug.
func TestSpeedAvoidsKeepAliveThirdRequestStall(t *testing.T) {
    var mu sync.Mutex
    hits := make(map[string]int)
    server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        mu.Lock()
        hits[r.RemoteAddr]++
        countOnConnection := hits[r.RemoteAddr]
        mu.Unlock()
        if countOnConnection > 2 {
            <-r.Context().Done()
            return
        }
        n, err := strconv.Atoi(r.URL.Query().Get("bytes"))
        if err != nil || r.URL.Path != "/__down" {
            w.WriteHeader(http.StatusBadRequest)
            return
        }
        w.Header().Set("Content-Length", strconv.Itoa(n))
        w.WriteHeader(http.StatusOK)
        if n > 0 {
            _, _ = w.Write(make([]byte, n))
        }
    }))
    defer server.Close()
    roots := x509.NewCertPool()
    roots.AddCert(server.Certificate())
    withRoots(t, roots)
    p := startProxy(t)
    result := SpeedTest(server.URL+"/__down", 4, 128<<10, time.Second, 5*time.Second)
    if result.Outcome != ProbeOK || len(result.Pings) != 4 || result.Received != 128<<10 {
        t.Fatalf("fresh protected TLS requests must work even if HTTP keep-alive stalls: %+v", result)
    }
    mu.Lock()
    connected := len(hits)
    mu.Unlock()
    if connected != 5 { // four small GETs plus a separate download
        t.Fatalf("expected independent TLS connections, got %d", connected)
    }
    select {
    case <-p.fds:
    default:
        t.Fatal("measurement bypassed protected Xray transport")
    }
}

func TestSpeedTestOutcomes(t *testing.T) {
	t.Run("не 200", func(t *testing.T) {
		u, roots := down(t, http.StatusForbidden, 1, 0, false)
		withRoots(t, roots)
		startProxy(t)
		if r := SpeedTest(u, 2, 1<<20, time.Second, 5*time.Second); r.Outcome != ProbeBadAnswer {
			t.Fatalf("ожидался ProbeBadAnswer: %+v", r)
		}
	})
	t.Run("чужой сертификат", func(t *testing.T) {
		u, _ := down(t, http.StatusOK, 1, 0, false)
		startProxy(t)
		if r := SpeedTest(u, 2, 1<<20, time.Second, 5*time.Second); r.Outcome != ProbeTLS {
			t.Fatalf("T5: ожидался ProbeTLS: %+v", r)
		}
	})
	t.Run("загрузка встала", func(t *testing.T) {
		u, roots := down(t, http.StatusOK, 1, 0, true)
		withRoots(t, roots)
		startProxy(t)
		if r := SpeedTest(u, 2, 1<<20, 300*time.Millisecond, 5*time.Second); r.Outcome != ProbeStalled || len(r.Pings) != 2 || r.Err == nil ||
            !strings.Contains(r.Err.Error(), "speed_stage=download_body") ||
            !strings.Contains(r.Err.Error(), "completed_pings=2") {
			t.Fatalf("ожидался ProbeStalled после пингов: %+v", r)
		}
	})
	t.Run("договор", func(t *testing.T) {
		startProxy(t)
		for _, bad := range []func() SpeedResult{
			func() SpeedResult { return SpeedTest("http://127.0.0.1/__down", 2, 1, time.Second, 5*time.Second) },
			func() SpeedResult { return SpeedTest("https://127.0.0.1/__down", 0, 1, time.Second, 5*time.Second) },
			func() SpeedResult { return SpeedTest("https://127.0.0.1/__down", 2, 1, 5*time.Second, time.Second) },
		} {
			if r := bad(); r.Outcome != ProbeContract {
				t.Fatalf("ожидался ProbeContract: %+v", r)
			}
		}
	})
	t.Run("ядро не запущено", func(t *testing.T) {
		setup(t)
		if r := SpeedTest("https://127.0.0.1/__down", 2, 1, time.Second, 5*time.Second); r.Outcome != ProbeNotRunning {
			t.Fatalf("ожидался ProbeNotRunning: %+v", r)
		}
	})
}
