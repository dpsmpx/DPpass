package bridge

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
)

// Учёт соединений (D-106) на поддельных часах: счётчики, маршрут и имя,
// закрытые — 5 минут, выключение стирает учтённое.

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time { return c.t }

func mbOf(n int) buf.MultiBuffer {
	b := buf.New()
	b.Extend(int32(n))
	return buf.MultiBuffer{b}
}

func fields(t *testing.T, line string) []string {
	t.Helper()
	f := strings.Split(line, "\t")
	if len(f) != 17 {
		t.Fatalf("в строке снимка %d полей, а не 17: %q", len(f), line)
	}
	return f
}

func TestConnTrackerCountsAndKeepsClosedFiveMinutes(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	tr := newConnTracker(clock.now)
	tr.setEnabled(true)
	ctx := session.ContextWithInbound(context.Background(), &session.Inbound{Tag: "tun-in", Source: xnet.TCPDestination(xnet.ParseAddress("172.19.0.1"), 40000)})
	_, c := tr.open(ctx, xnet.TCPDestination(xnet.ParseAddress("198.51.100.7"), 443))
	if c == nil {
		t.Fatal("включённый учёт не открыл запись")
	}
	clock.t = clock.t.Add(30 * time.Millisecond)
	c.count(true, mbOf(517))
	clock.t = clock.t.Add(70 * time.Millisecond)
	c.count(false, mbOf(1400))
	c.count(false, append(mbOf(1400), mbOf(200)...))
	// Маршрут и имя — как их записал бы диспетчер ядра до исходящего.
	c.ob.Tag = "proxy"
	c.ob.RouteTarget = xnet.TCPDestination(xnet.ParseAddress("example.com"), 443)
	c.content.Protocol = "tls"
	c.capture()
	clock.t = clock.t.Add(2 * time.Second)

	lines, on, skipped := tr.snapshot()
	if !on || skipped != 0 || len(lines) != 1 {
		t.Fatalf("снимок: %d строк, включён %v, пропущено %d", len(lines), on, skipped)
	}
	f := fields(t, lines[0])
	want := []string{"1", "tcp", "tun-in", "172.19.0.1:40000", "198.51.100.7:443", "example.com", "tls", "proxy", "o", "2100", "2100", "2000", "100", "517", "3000", "1", "3"}
	for i := range want {
		if f[i] != want[i] {
			t.Errorf("поле %d: %q, ожидалось %q (%q)", i, f[i], want[i], lines[0])
		}
	}

	c.finish(false)
	c.finish(true) // второй раз — ничего: итог уже записан
	clock.t = clock.t.Add(time.Second)
	lines, _, _ = tr.snapshot()
	if f := fields(t, lines[0]); f[8] != "c" || f[10] != "2100" {
		t.Fatalf("закрытое: состояние %q, длилось %q мс", f[8], f[10])
	}
	clock.t = clock.t.Add(connRetain)
	if lines, _, _ = tr.snapshot(); len(lines) != 0 {
		t.Fatalf("закрытое держится дольше %v: %v", connRetain, lines)
	}
}

func TestConnTrackerOffMeansNothingAndForgets(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	tr := newConnTracker(clock.now)
	if _, c := tr.open(context.Background(), xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 53)); c != nil {
		t.Fatal("выключенный учёт открыл запись")
	}
	tr.setEnabled(true)
	_, c := tr.open(context.Background(), xnet.UDPDestination(xnet.ParseAddress("192.0.2.1"), 53))
	c.finish(true)
	lines, _, _ := tr.snapshot()
	if f := fields(t, lines[0]); f[1] != "udp" || f[8] != "e" || f[12] != "-1" {
		t.Fatalf("прерванное без ответа: %q", lines[0])
	}
	tr.setEnabled(false)
	if lines, on, _ := tr.snapshot(); on || len(lines) != 0 {
		t.Fatalf("выключение не стёрло учтённое: %v", lines)
	}
}

func TestConnTrackerLimitsLiveAndClosed(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	tr := newConnTracker(clock.now)
	tr.setEnabled(true)
	dest := xnet.TCPDestination(xnet.ParseAddress("192.0.2.1"), 80)
	var open []*trackedConn
	for range connMaxLive + 3 {
		if _, c := tr.open(context.Background(), dest); c != nil {
			open = append(open, c)
		}
	}
	if len(open) != connMaxLive {
		t.Fatalf("открытых учтено %d, предел %d", len(open), connMaxLive)
	}
	if _, _, skipped := tr.snapshot(); skipped != 3 {
		t.Fatalf("сверх предела не учтено %d, ожидалось 3", skipped)
	}
	for _, c := range open {
		c.finish(false)
	}
	lines, _, _ := tr.snapshot()
	if len(lines) != connMaxClosed {
		t.Fatalf("закрытых держится %d, предел %d", len(lines), connMaxClosed)
	}
	// Новые — первыми, старые закрытые ушли.
	if f := fields(t, lines[0]); f[0] != "4096" {
		t.Fatalf("первым — не последнее: %q", f[0])
	}
}

func TestCleanKeepsSnapshotLinesWhole(t *testing.T) {
	if got := clean("a\tb\nc\rd"); got != "a b c d" {
		t.Fatalf("clean: %q", got)
	}
}

// Ответ входа прокси: ошибка чтения — конец соединения (EOF — штатный).
type endReader struct{ err error }

func (r endReader) ReadMultiBuffer() (buf.MultiBuffer, error) { return nil, r.err }

func TestDispatchLinksEndTheConnection(t *testing.T) {
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	tr := newConnTracker(clock.now)
	tr.setEnabled(true)
	dest := xnet.TCPDestination(xnet.ParseAddress("198.51.100.7"), 80)
	state := func(c *trackedConn) string {
		tr.mu.Lock()
		defer tr.mu.Unlock()
		return c.state
	}
	cases := []struct {
		name string
		end  func(c *trackedConn)
		want string
	}{
		// Вход простого HTTP закрывает запрос, дочитав ответ: соединение закончено.
		{"запрос закрыт входом", func(c *trackedConn) { (&countingWriter{Writer: buf.Discard, c: c, up: true, owned: true}).Close() }, connClosed},
		{"запрос прерван входом", func(c *trackedConn) { (&countingWriter{Writer: buf.Discard, c: c, up: true, owned: true}).Interrupt() }, connFailed},
		{"ответ дочитан", func(c *trackedConn) {
			(&countingReader{Reader: endReader{io.EOF}, c: c, ends: true}).ReadMultiBuffer()
		}, connClosed},
		{"ответ оборван", func(c *trackedConn) {
			(&countingReader{Reader: endReader{io.ErrClosedPipe}, c: c, ends: true}).ReadMultiBuffer()
		}, connFailed},
	}
	for _, tc := range cases {
		_, c := tr.open(context.Background(), dest)
		tc.end(c)
		if got := state(c); got != tc.want {
			t.Errorf("%s: состояние %q, а не %q", tc.name, got, tc.want)
		}
	}
	// Канал ответа DispatchLink закрывает исходящий: это не конец, конец — возврат DispatchLink.
	_, c := tr.open(context.Background(), dest)
	(&countingWriter{Writer: buf.Discard, c: c, ends: true}).Close()
	if got := state(c); got != connOpen {
		t.Errorf("закрытие канала ответа DispatchLink закончило соединение: %q", got)
	}
}
