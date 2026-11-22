//go:build linux

package bridge

// Эксперимент с началом соединения (D-116, docs/research/FAKE_PACKETS.md,
// вариант «а»): перестановка частей и подделка с малым TTL — только для
// замера А/Б (§6.2), за выключенным по умолчанию переключателем. Обычное
// подключение этого кода не касается: приём получают только соединения
// исходящих с тегом [expTagPrefix], а такие компилятор собирает лишь для
// попыток замера.
//
// Как соединение попадает сюда: Xray зовёт системный «набиратель»
// (`internet.UseAlternativeSystemDialer`). Наш — обёртка над стандартным
// `internet.DefaultSystemDialer`: тот по-прежнему применяет хуки
// `RegisterDialerController`, и защита сокетов (D-25, protect.go) не
// меняется. Тег исходящего — из контекста соединения
// (`session.OutboundsFromContext`): последний — тот, кто набирает сокет.
//
// Что делается с первой записью — ClientHello TLS, в котором найдено имя
// (SNI); иначе запись уходит как есть, а попытка считается «пропущенной»:
// - перестановка: начало до середины имени — с TTL 1 (гибнет на первом
//   узле), остальное — с обычным TTL; потерянное начало ядро ОС повторит
//   само, уже с обычным TTL;
// - подделка с TTL n: начало до середины имени уходит из страницы памяти
//   вне кучи Go через vmsplice и splice — ядро ОС ссылается на эту
//   страницу, не копируя; в ней сначала подложные байты (имя заменено
//   случайными буквами той же длины), TTL — n; как сегмент ушёл, на ту же
//   страницу пишутся настоящие байты и TTL возвращается. Подделка гибнет в
//   пути, и ядро ОС повторяет сегмент — уже с настоящими байтами.
// Свой код по публичному описанию приёма (FAKE_PACKETS.md, §2; D-20).

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/dpsmpx/dppass/tools/xray/zapret2"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

// expTagPrefix — тег исходящего эксперимента; дальше — вид приёма:
// "disorder", "split" или "fake-<ttl>". Договор с XrayBackend.TAG_EXPERIMENT (Kotlin).
const expTagPrefix = "dppass:exp-"

// desyncKind — вид приёма.
type desyncKind uint8

const (
	desyncDisorder desyncKind = 1
	desyncFake     desyncKind = 2
	desyncSplit    desyncKind = 3
	desyncSplitFirst desyncKind = 4
	desyncAuto desyncKind = 5
)

type desyncMode struct {
	kind desyncKind
	ttl  int // TTL подделки; у перестановки — 1
}

// Пределы TTL подделки: 1 гибнет на первом узле; больше 64 — дальше любого
// пути, подделка дошла бы до сервера.
const (
	minFakeTTL = 1
	maxFakeTTL = 64
)

// sentWait — сколько ждать, пока ядро ОС отправит первую часть, прежде чем
// вернуть TTL: иначе первая отправка могла бы уйти уже с обычным TTL.
const (
	sentWait = 200 * time.Millisecond
	sentPoll = time.Millisecond
)

// fakeHold — сколько держать подделку на странице после того, как очередь
// сокета опустела. Ядро ОС не копирует байты при splice: сегмент ссылается
// на страницу, и драйвер (или, на стенде, соседний конец veth) читает её
// позже, чем TCP считает сегмент отправленным. Перезаписать страницу сразу —
// и в сеть ушли бы настоящие байты с малым TTL (стенд это ловит). Выдержка —
// параметр эксперимента, а не гарантия: на телефоне очередь модема может
// быть длиннее (D-116).
const fakeHold = 30 * time.Millisecond

var (
	desyncApplied atomic.Int64
	desyncSkipped atomic.Int64
	dialerOnce    sync.Once
)

// DesyncStats — сколько соединений эксперимента получили приём и сколько
// ушли как есть (не ClientHello, имени нет, отказ системы) с запуска
// процесса. Замер А/Б сверяет по ним, что приём действительно был.
func DesyncStats() (applied, skipped int64) {
	return desyncApplied.Load(), desyncSkipped.Load()
}

// parseDesyncTag adapts the single shared Zapret2 strategy registry to
// the Xray bridge's legacy transport fields.
func parseDesyncTag(tag string) (desyncMode, bool, error) {
    mode, ok, err := zapret2.ParseTag(tag)
    if !ok || err != nil { return desyncMode{}, ok, err }
    switch mode.Kind {
    case zapret2.Disorder: return desyncMode{kind: desyncDisorder, ttl: mode.TTL}, true, nil
    case zapret2.Fake: return desyncMode{kind: desyncFake, ttl: mode.TTL}, true, nil
    case zapret2.Split: return desyncMode{kind: desyncSplit}, true, nil
    case zapret2.SplitFirst: return desyncMode{kind: desyncSplitFirst}, true, nil
    case zapret2.Auto: return desyncMode{kind: desyncAuto}, true, nil
    default: return desyncMode{}, true, fmt.Errorf("unknown Zapret2 mode %v", mode.Kind)
    }
}

// installDesyncDialer ставит обёртку набирателя — один раз на процесс,
// после хука защиты: хук регистрируется, пока набиратель стандартный.
func installDesyncDialer() {
	dialerOnce.Do(func() {
		internet.UseAlternativeSystemDialer(&desyncDialer{base: &internet.DefaultSystemDialer{}})
	})
}

type desyncDialer struct {
	base internet.SystemDialer
}

func (d *desyncDialer) Dial(ctx context.Context, src xnet.Address, dest xnet.Destination, sockopt *internet.SocketConfig) (net.Conn, error) {
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
	if err != nil {
		return conn, err
	}
	// Experimental tag is only consulted on TCP/UDP outbound sockets.
	// Ordinary subscriptions, DNS and other traffic retain the stock dialer.
	if dest.Network != xnet.Network_TCP && dest.Network != xnet.Network_UDP {
		return conn, nil
	}
	obs := session.OutboundsFromContext(ctx)
	if len(obs) == 0 {
		return conn, nil
	}
	mode, ok, perr := parseDesyncTag(obs[len(obs)-1].Tag)
	if !ok {
		return conn, nil
	}
	if perr != nil {
		// An explicitly selected but invalid DPI profile must never be
		// interpreted as an ordinary unmodified direct connection.
		desyncSkipped.Add(1)
		_ = conn.Close()
		return nil, fmt.Errorf("invalid Zapret2 strategy: %w", perr)
	}
	if dest.Network == xnet.Network_TCP {
		tcp, isTCP := conn.(*net.TCPConn)
		if !isTCP {
			desyncSkipped.Add(1)
			return conn, nil
		}
		// Use the actual protected socket destination only as fallback when
		// TLS ECH or a fragmented ClientHello hides the SNI. No names logged.
		return &desyncConn{TCPConn: tcp, mode: mode, host: tcp.RemoteAddr().(*net.TCPAddr).IP.String()}, nil
	}
	udp, isUDP := conn.(*net.UDPConn)
	if !isUDP {
		desyncSkipped.Add(1)
		return conn, nil
	}
	return &desyncUDPConn{UDPConn: udp, mode: mode, host: udp.RemoteAddr().(*net.UDPAddr).IP.String()}, nil
}

func (d *desyncDialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

// desyncConn — соединение эксперимента: приём — только на первой записи.
type desyncConn struct {
	*net.TCPConn
	mode  desyncMode
	first sync.Once
	plannerErr error
    host string
    adaptiveSelection atomic.Pointer[adaptivePick]
    received atomic.Int64
    observed sync.Once
}

// net.TCPConn promotes io.ReaderFrom and io.WriterTo through embedding.
// io.Copy in Xray is allowed to select these optimized methods instead of
// calling our Write/Read overrides. That would silently bypass the first
// ClientHello strategy *and* downstream evidence collection. Hide both
// optimizations behind interface-only wrappers so all bytes go through the
// adapter's interception and counters.
func (c *desyncConn) ReadFrom(r io.Reader) (int64, error) {
    return io.Copy(struct{ io.Writer }{c}, r)
}

func (c *desyncConn) WriteTo(w io.Writer) (int64, error) {
    return io.Copy(w, struct{ io.Reader }{c})
}

// Read observes actual downstream bytes, not mere TCP dial/TLS readiness.
// It does not consume data; Xray receives every byte normally.
func (c *desyncConn) Read(b []byte) (int, error) {
    n, err := c.TCPConn.Read(b)
    if n > 0 {
        total := c.received.Add(int64(n))
        if total >= adaptivePayloadThreshold {
            if selected := c.adaptiveSelection.Load(); selected != nil {
                // Learn from long-lived HTTP/2/QUIC streams before Close.
                c.observed.Do(func() {
                    zapret2Auto.observeTracked(selected.host, selected.strategy, total, selected.generation)
                })
            }
        }
    }
    return n, err
}

func (c *desyncConn) Close() error {
    c.observed.Do(func() {
        if selected := c.adaptiveSelection.Load(); selected != nil {
            zapret2Auto.observeTracked(selected.host, selected.strategy, c.received.Load(), selected.generation)
        }
    })
    return c.TCPConn.Close()
}

func (c *desyncConn) Write(b []byte) (int, error) {
	n := 0
	var err error
	done := false
	c.first.Do(func() {
		done = true
		n, err = c.desyncFirst(b)
	})
	if done {
		return n, err
	}
	if c.plannerErr != nil { return 0, c.plannerErr }
	return c.TCPConn.Write(b)
}

// desyncFirst — первая запись с приёмом; не вышло до отправки хоть байта —
// запись как есть.
func (c *desyncConn) desyncFirst(b []byte) (int, error) {
    // Adaptive mode is strictly per *new* protected TCP connection; live
    // streams must not change their packet strategy after ClientHello.
    // Only recognized TLS/HTTP headers can safely enter auto-selection.
    s, e, hostnameFound := zapret2.FirstHostRange(b)
    if hostnameFound {
        c.host = canonicalAdaptiveHost(string(b[s:e]))
    }
    eligible := hostnameFound || zapret2.IsTLSClientHelloPrefix(b)
    if c.mode.kind == desyncAuto && !eligible {
        desyncSkipped.Add(1)
        return c.TCPConn.Write(b)
    }
    if eligible && (c.mode.kind == desyncAuto || zapret2Auto.wants(c.host)) {
        choice, generation := zapret2Auto.chooseTracked(c.host)
        resolved, ok, err := parseDesyncTag(zapret2.TagPrefix + choice)
        if !ok || err != nil || resolved.kind == desyncAuto {
            c.plannerErr = fmt.Errorf("adaptive strategy selection rejected: %v", err)
            return 0, c.plannerErr
        }
        c.mode = resolved
        c.adaptiveSelection.Store(&adaptivePick{host: c.host, strategy: choice, generation: generation})
    }
    // Strategy decisions and offsets still come from the shared Go planner,
    // including Alpine over its app-private Unix socket.
    plan, err := zapret2.PlanFor(modeTag(c.mode), "tcp", b)
    if err != nil {
        // Do not silently pass original TLS if the chosen Alpine daemon dies.
        c.plannerErr = err
        return 0, err
    }
    if !plan.Applied {
        desyncSkipped.Add(1)
        return c.TCPConn.Write(b)
    }
    if plan.Cut == 1 {
        return c.splitFirstTLS(b)
    }
    if plan.Cut <= 0 || plan.Cut >= len(b) { 
        c.plannerErr = errors.New("Alpine planner returned invalid TCP split")
        return 0, c.plannerErr
    }
    var sent int
    switch c.mode.kind {
    case desyncDisorder:
        sent, err = c.lowTTLWrite(b[:plan.Cut])
    case desyncFake:
        if len(plan.Fake) != plan.Cut {
            c.plannerErr = errors.New("Alpine planner returned invalid decoy")
            return 0, c.plannerErr
        }
        sent, err = c.fakeWrite(b[:plan.Cut], plan.Fake)
    case desyncSplit:
        sent, err = c.TCPConn.Write(b[:plan.Cut])
    default:
        c.plannerErr = errors.New("invalid Zapret2 strategy")
        return 0, c.plannerErr
    }
    if err != nil || sent != plan.Cut {
        // Never silently turn a failed low-TTL / vmsplice attempt into
        // ordinary direct TLS/HTTP: that bypasses the selected strategy.
        if err == nil { err = errors.New("short Zapret2 TCP injection write") }
        desyncSkipped.Add(1)
        c.plannerErr = fmt.Errorf("Zapret2 TCP strategy failed: %w", err)
        return sent, c.plannerErr
    }
    desyncApplied.Add(1)
    m, err := c.TCPConn.Write(b[plan.Cut:])
    if err != nil || m != len(b)-plan.Cut {
        if err == nil { err = errors.New("short Zapret2 TCP tail write") }
        c.plannerErr = fmt.Errorf("Zapret2 TCP tail failed: %w", err)
        return sent+m, c.plannerErr
    }
    return sent+m, nil
}

// modeTag is only an adapter from the existing Xray Kotlin wire contract
// to the shared Linux/Alpine strategy catalog; it does not choose offsets.
func modeTag(m desyncMode) string {
    switch m.kind {
    case desyncDisorder: return zapret2.TagPrefix + "disorder"
    case desyncSplit: return zapret2.TagPrefix + "split"
    case desyncSplitFirst: return zapret2.TagPrefix + "split-1"
    case desyncFake: return fmt.Sprintf("%sfake-%d", zapret2.TagPrefix, m.ttl)
    case desyncAuto: return zapret2.TagPrefix + "auto"
    }
    return zapret2.TagPrefix + "unsupported"
}

// splitFirstTLS sends an unchanged ClientHello in two TCP writes. It is
// also the safe fallback for name-dependent strategies when no SNI is
// visible: inventing a fake hostname would corrupt a real handshake.
func (c *desyncConn) splitFirstTLS(b []byte) (int, error) {
	n, err := c.TCPConn.Write(b[:1])
	if err != nil || n != 1 {
        if err == nil { err = errors.New("short TLS first-byte write") }
        c.plannerErr = fmt.Errorf("Zapret2 TLS split failed: %w", err)
		return n, c.plannerErr
	}
	time.Sleep(2 * time.Millisecond)
	m, err := c.TCPConn.Write(b[1:])
	if err != nil || m != len(b)-1 {
        if err == nil { err = errors.New("short TLS tail write") }
        c.plannerErr = fmt.Errorf("Zapret2 TLS split failed: %w", err)
        return n + m, c.plannerErr
    }
    desyncApplied.Add(1)
	return n + m, nil
}

// lowTTLWrite — перестановка: часть с TTL 1, затем TTL прежний.
func (c *desyncConn) lowTTLWrite(part []byte) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	restore, err := setTTL(rc, c.v6(), 1)
	if err != nil {
		return 0, err
	}
	n, werr := c.TCPConn.Write(part)
	waitSent(rc)
	if rerr := restore(); rerr != nil && werr == nil {
		werr = rerr
	}
	return n, werr
}

// fakeWrite — подделка: [fake] с TTL n из страницы вне кучи Go, после
// отправки на её место — [real], TTL прежний. Ядро ОС повторит сегмент со
// страницы — с настоящими байтами.
func (c *desyncConn) fakeWrite(real, fake []byte) (int, error) {
	if len(real) != len(fake) || len(real) == 0 || len(real) > unix.Getpagesize() {
		return 0, errors.New("часть для подделки не помещается в страницу")
	}
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	page, err := unix.Mmap(-1, 0, unix.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return 0, err
	}
	// Страница остаётся у ядра ОС, пока сегмент не подтверждён: снятие
	// отображения её не освобождает — ссылка у буфера сокета.
	defer func() { _ = unix.Munmap(page) }()
	copy(page, fake)
	var pipe [2]int
	if err := unix.Pipe2(pipe[:], unix.O_CLOEXEC); err != nil {
		return 0, err
	}
	defer func() { _ = unix.Close(pipe[0]); _ = unix.Close(pipe[1]) }()
	restore, err := setTTL(rc, c.v6(), c.mode.ttl)
	if err != nil {
		return 0, err
	}
	iov := []unix.Iovec{{Base: &page[0]}}
	iov[0].SetLen(len(real))
	if _, err := unix.Vmsplice(pipe[1], iov, 0); err != nil {
		_ = restore()
		return 0, err
	}
	sent := 0
	var serr error
	// Сокет неблокирующий (netpoller Go): ждать, пока примет, — через Write.
	werr := rc.Write(func(fd uintptr) bool {
		for sent < len(real) {
			n, err := unix.Splice(pipe[0], nil, int(fd), nil, len(real)-sent, unix.SPLICE_F_NONBLOCK)
			if err == unix.EAGAIN {
				return false
			}
			if err != nil {
				serr = err
				return true
			}
			sent += int(n)
		}
		return true
	})
	if serr == nil {
		serr = werr
	}
	waitSent(rc)
	time.Sleep(fakeHold)
	copy(page, real)
	if rerr := restore(); rerr != nil && serr == nil {
		serr = rerr
	}
	return sent, serr
}

func (c *desyncConn) v6() bool {
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	return ok && a.IP.To4() == nil
}

// setTTL ставит TTL (IPv6 — число узлов) сокета и возвращает возврат прежнего.
func setTTL(rc syscall.RawConn, v6 bool, ttl int) (func() error, error) {
	level, opt := unix.IPPROTO_IP, unix.IP_TTL
	if v6 {
		level, opt = unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS
	}
	var old int
	var err error
	if cerr := rc.Control(func(fd uintptr) {
		old, err = unix.GetsockoptInt(int(fd), level, opt)
		if err == nil {
			err = unix.SetsockoptInt(int(fd), level, opt, ttl)
		}
	}); cerr != nil {
		return nil, cerr
	}
	if err != nil {
		return nil, err
	}
	return func() error {
		var rerr error
		if cerr := rc.Control(func(fd uintptr) { rerr = unix.SetsockoptInt(int(fd), level, opt, old) }); cerr != nil {
			return cerr
		}
		return rerr
	}, nil
}

// waitSent — ждать, пока в очереди сокета не останется неотправленного
// (TCP_INFO, tcpi_notsent_bytes), не дольше [sentWait].
func waitSent(rc syscall.RawConn) {
	deadline := time.Now().Add(sentWait)
	for time.Now().Before(deadline) {
		var left uint32
		var err error
		if cerr := rc.Control(func(fd uintptr) {
			var info *unix.TCPInfo
			info, err = unix.GetsockoptTCPInfo(int(fd), unix.IPPROTO_TCP, unix.TCP_INFO)
			if err == nil {
				left = info.Notsent_bytes
			}
		}); cerr != nil || err != nil || left == 0 {
			return
		}
		time.Sleep(sentPoll)
	}
}

// desyncUDPConn sends low-TTL decoys *before each eligible QUIC Initial*,
// including retries, while bounding the number of initial flights. It is not
// equivalent to nfqws2's packet-level NFQUEUE engine. Genuine payloads are
// sent only after successful decoys and original TTL restoration. Other UDP
// datagrams are unmodified; additional Initials beyond the budget fail closed.
type desyncUDPConn struct {
	*net.UDPConn
	mode desyncMode
	mu sync.Mutex
    initialFlights int
	plannerErr error
    host string
    adaptiveSelection atomic.Pointer[adaptivePick]
    received atomic.Int64
    observed sync.Once
}

func (c *desyncUDPConn) Read(b []byte) (int, error) {
    n, err := c.UDPConn.Read(b)
    if n > 0 {
        total := c.received.Add(int64(n))
        if total >= adaptivePayloadThreshold {
            if selected := c.adaptiveSelection.Load(); selected != nil {
                c.observed.Do(func() {
                    zapret2Auto.observeTracked(selected.host, selected.strategy, total, selected.generation)
                })
            }
        }
    }
    return n, err
}

func (c *desyncUDPConn) Close() error {
    c.observed.Do(func() {
        if pick := c.adaptiveSelection.Load(); pick != nil {
            zapret2Auto.observeTracked(pick.host, pick.strategy, c.received.Load(), pick.generation)
        }
    })
    return c.UDPConn.Close()
}

const dummyQuicRepeats = 6

// Bound per-connection injection work. After the budget is exhausted we
// reject additional Initial retransmissions instead of quietly sending
// the initial handshake without its selected DPI strategy.
const maxQuicInitialFlights = 8

func (c *desyncUDPConn) Write(b []byte) (int, error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    if c.plannerErr != nil { return 0, c.plannerErr }
    if (c.mode.kind == desyncAuto || zapret2Auto.wants(c.host)) && zapret2.IsQUICInitial(b) {
        // Apply one chosen TTL for this UDP flow, including retransmitted
        // Initials; no silent fallback to unmodified QUIC on injection error.
        if c.adaptiveSelection.Load() == nil {
            choice, generation := zapret2Auto.chooseQUICTracked(c.host)
            resolved, ok, err := parseDesyncTag(zapret2.TagPrefix + choice)
            if !ok || err != nil || resolved.kind != desyncFake {
                c.plannerErr = fmt.Errorf("adaptive QUIC strategy rejected: %v", err)
                return 0, c.plannerErr
            }
            c.mode = resolved
            c.adaptiveSelection.Store(&adaptivePick{host:"udp:"+c.host, strategy:choice, generation:generation})
        }
    }

    // QUIC clients can send a non-Initial datagram first and then retry
    // Initial multiple times. Checking only the very first Write allowed
    // every later Initial to bypass the selected strategy. This classifier
    // is shared with the Alpine planner; no independent parser lives here.
    if c.mode.kind != desyncFake || !zapret2.IsQUICInitial(b) {
        return c.UDPConn.Write(b)
    }
    if c.initialFlights >= maxQuicInitialFlights {
        c.plannerErr = errors.New("Zapret2 QUIC Initial retry limit reached")
        desyncSkipped.Add(1)
        return 0, c.plannerErr
    }
    // Alpine remains the strategy authority. Android only checks whether
    // a planner call is needed and performs the protected socket writes.
    plan, err := zapret2.PlanFor(modeTag(c.mode), "udp", b)
    if err != nil {
        c.plannerErr = err
        return 0, err
    }
    if !plan.Applied {
        desyncSkipped.Add(1)
        return c.UDPConn.Write(b)
    }
    c.initialFlights++
    if err := c.sendLowTTLDummyQUIC(plan.Fake, plan.Repeats); err != nil {
        // A failed decoy is not a successful strategy; never send
        // this QUIC Initial unmodified as a fallback.
        desyncSkipped.Add(1)
        c.plannerErr = fmt.Errorf("Zapret2 QUIC decoy failed: %w", err)
        return 0, c.plannerErr
    }
    desyncApplied.Add(1)
    return c.UDPConn.Write(b)
}

// The caller transmits the genuine QUIC Initial only after every decoy
// write and original TTL restoration succeeded.
func (c *desyncUDPConn) sendLowTTLDummyQUIC(fake []byte, repeats int) error {
    rc, err := c.SyscallConn()
    if err != nil { return err }
    v6 := false
    if a, ok := c.RemoteAddr().(*net.UDPAddr); ok { v6 = a.IP.To4() == nil }
    restore, err := setTTL(rc, v6, c.mode.ttl)
    if err != nil { return err }
    var sendErr error
    for i := 0; i < repeats; i++ {
        n, e := c.UDPConn.Write(fake)
        if e != nil { sendErr = e; break }
        if n != len(fake) { sendErr = errors.New("short QUIC decoy write"); break }
    }
    if err := restore(); err != nil && sendErr == nil { sendErr = err }
    return sendErr
}


// All packet classifiers and decoy constructors are owned by zapret2.
// Retained package-local names here keep the existing bridge test contract
// and platform transport adapters stable during the migration.
func fakeQUICInitial(b []byte) []byte { return zapret2.FakeQUICInitial(b) }
func isQUICInitial(b []byte) bool { return zapret2.IsQUICInitial(b) }
func isTLSClientHelloPrefix(b []byte) bool { return zapret2.IsTLSClientHelloPrefix(b) }
func firstHostRange(b []byte) (int, int, bool) { return zapret2.FirstHostRange(b) }
func httpHostRange(b []byte) (int, int, bool) { return zapret2.HTTPHostRange(b) }
func fakeChunk(b []byte, start, end int) []byte { return zapret2.FakeChunk(b, start, end) }
func sniRange(b []byte) (int, int, bool) { return zapret2.SNIRange(b) }
