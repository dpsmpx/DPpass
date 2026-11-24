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
	"encoding/binary"
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
	"github.com/dpsmpx/dppass/tools/xray/localdpi"
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
    desyncTLSRecordSplit desyncKind = 6
    desyncPass desyncKind = 7
    desyncSplitSecond desyncKind = 8
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
    case zapret2.SplitSecond: return desyncMode{kind: desyncSplitSecond}, true, nil
    case zapret2.TLSRecordSplit: return desyncMode{kind: desyncTLSRecordSplit}, true, nil
    case zapret2.Pass: return desyncMode{kind: desyncPass}, true, nil
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
	generation := passiveQualityGeneration()
    ip := net.ParseIP(dest.Address.String())
    var routeGeneration uint64
    localExperimental := false
    if dest.Network == xnet.Network_TCP && isIPv6Peer(ip) {
        obs := session.OutboundsFromContext(ctx)
        if len(obs) > 0 { _, localExperimental, _ = parseDesyncTag(obs[len(obs)-1].Tag) }
        if localExperimental {
            routeGeneration = zapret2Auto.generationSnapshot()
            if liveIPv6.skip(ip, routeGeneration, time.Now()) { return nil, syscall.ENETUNREACH }
        }
    }
	conn, err := d.base.Dial(ctx, src, dest, sockopt)
    if localExperimental { liveIPv6.result(ip, routeGeneration, time.Now(), err) }
	if err != nil {
        // Count failed experimental dials, never ordinary Xray or DoH sockets.
        if dest.Network == xnet.Network_TCP {
            obs := session.OutboundsFromContext(ctx)
            if len(obs) > 0 {
                if _, ok, _ := parseDesyncTag(obs[len(obs)-1].Tag); ok {
                    recordZapret2DialFailureWithIP(err, net.ParseIP(dest.Address.String()))
                }
            }
        }
		return conn, err
	}
	if dest.Network == xnet.Network_TCP {
        if tcp, ok := conn.(*net.TCPConn); ok && !tcp.RemoteAddr().(*net.TCPAddr).IP.IsLoopback() {
            trackPassiveTCP(tcp, generation)
        }
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
        zapret2Stage.tcpDialOK.Add(1)
        recordZapret2DialSuccessFamily(tcp.RemoteAddr().(*net.TCPAddr).IP)
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
	// Only the first complete ClientHello is eligible for a strategy. TLS
	// writers may split that record across several Write calls; accumulate
	// it briefly instead of consuming the one-shot hook on an incomplete
	// fragment. writeMu also serializes the pending timer and actual writes.
	writeMu sync.Mutex
	firstDone bool
	pending []byte
	pendingTimer *time.Timer
	plannerErr error
    host string
    adaptiveSelection atomic.Pointer[adaptivePick]
    received atomic.Int64
    observed sync.Once
    stageHelloSent atomic.Bool
    stageFirstReply atomic.Bool
    stageReadTimedOut atomic.Bool
    stageCloseRecorded atomic.Bool
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
    // Avoid deadlocking a peer that waits for our first partial record before
    // replying: a Read is a request to send any pending handshake fragments.
    if err := c.flushFirstBeforeRead(); err != nil { return 0, err }
    n, err := c.TCPConn.Read(b)
    if n > 0 {
        if c.stageFirstReply.CompareAndSwap(false, true) {
            zapret2Stage.tcpFirstReply.Add(1)
            if isTLSAlertRecordHeader(b[:n]) {
                zapret2Stage.tcpFirstTLSAlert.Add(1)
            } else if pick := c.adaptiveSelection.Load(); pick != nil && pick.strategy == "pass" {
                zapret2Auto.retainPlainReply(pick.host, pick.generation)
            }
        }
        total := c.received.Add(int64(n))
        if total >= adaptivePayloadThreshold {
            if selected := c.adaptiveSelection.Load(); selected != nil {
                // Learn from long-lived HTTP/2/QUIC streams before Close.
                c.observed.Do(func() {
                    recordLocalSocketEvidence(selected, localdpi.SocketClose(total))
                })
            }
        }
    }
    if err != nil && c.stageHelloSent.Load() && !c.stageFirstReply.Load() &&
        isZapret2Timeout(err) && c.stageReadTimedOut.CompareAndSwap(false, true) {
        zapret2Stage.tcpReadTimeout.Add(1)
        // A timed-out ClientHello can remain open indefinitely. Teach AUTO
        // about the zero-byte stall for future flows, not the current stream.
        if c.received.Load() == 0 {
            if pick := c.adaptiveSelection.Load(); pick != nil {
                // Distinguish an actual first-reply timeout from a benign
                // application Close: only the former triggers AUTO backoff.
                recordLocalSocketEvidence(pick, localdpi.SocketFirstReplyTimeout(true, false, 0))
            }
        }
    }
    return n, err
}

// Both socket transports feed the same evidence contract. A transport
// reply is not verified application content; ordinary closes are neutral.
func recordLocalSocketEvidence(pick *adaptivePick, evidence localdpi.Evidence) {
    if !socketEvidenceAdmissible(pick, evidence) { return }
    switch evidence.Kind {
    case localdpi.Downstream:
        zapret2Auto.observeTracked(pick.host, pick.strategy, evidence.Bytes, pick.generation)
    case localdpi.FirstReplyTimeout:
        zapret2Auto.observeStallTracked(pick.host, pick.strategy, pick.generation)
    }
}

func (c *desyncConn) Close() error {
    // The final buffered bytes were already accepted by Write. Attempt to
    // transmit them before closing; a failure remains sticky.
    pendingErr := c.flushFirstBeforeRead()
    if c.stageHelloSent.Load() && !c.stageFirstReply.Load() && c.stageCloseRecorded.CompareAndSwap(false, true) {
        zapret2Stage.tcpClosedNoReply.Add(1)
    }
    c.observed.Do(func() {
        if selected := c.adaptiveSelection.Load(); selected != nil {
            total := c.received.Load()
            // Zero-byte Close is ambiguous: cancellation, reconnect or
            // shutdown may end a healthy in-flight request. Only the
            // explicit read-timeout path supplies a negative observation.
            recordLocalSocketEvidence(selected, localdpi.SocketClose(total))
        }
    })
    closeErr := c.TCPConn.Close()
    if pendingErr != nil { return pendingErr }
    return closeErr
}

// An incomplete ClientHello can be spread over many TCP Write calls.
// Buffer only a bounded TLS record, and only for a short time. Raw TCP and
// HTTP follow the previous immediate path. No host or payload is logged.
const (
    maxFirstTLSRecord = 5 + 16*1024
    firstTLSBufferTimeout = 50 * time.Millisecond
)

func needsMoreFirstTLS(b []byte) bool {
    if len(b) == 0 || len(b) > maxFirstTLSRecord || b[0] != 22 { return false }
    if len(b) >= 2 && b[1] != 3 { return false }
    if len(b) >= 3 && b[2] > 4 { return false }
    if len(b) >= 6 && b[5] != 1 { return false }
    if len(b) < 5 { return true }
    size := int(binary.BigEndian.Uint16(b[3:5]))
    if size < 4 || size > 16*1024 { return false }
    return len(b) < 5+size
}

// flushFirstLocked sends the entire buffered record at most once and never
// retries a failed DPI write as plain TCP. The caller holds writeMu.
func (c *desyncConn) flushFirstLocked() error {
    if c.firstDone || len(c.pending) == 0 { return c.plannerErr }
    c.firstDone = true
    if c.pendingTimer != nil { c.pendingTimer.Stop(); c.pendingTimer = nil }
    payload := c.pending
    c.pending = nil
    isHello := zapret2.IsTLSClientHelloPrefix(payload)
    n, err := c.desyncFirst(payload)
    if err == nil && n != len(payload) { err = io.ErrShortWrite }
    if isHello {
        if err == nil {
            c.stageHelloSent.Store(true)
            zapret2Stage.tcpHelloSent.Add(1)
        } else {
            zapret2Stage.tcpHelloFailed.Add(1)
        }
    }
    if err != nil {
        c.plannerErr = fmt.Errorf("Zapret2 first TCP record failed: %w", err)
    }
    return c.plannerErr
}

func (c *desyncConn) flushFirstBeforeRead() error {
    c.writeMu.Lock()
    defer c.writeMu.Unlock()
    return c.flushFirstLocked()
}

func (c *desyncConn) Write(b []byte) (int, error) {
    c.writeMu.Lock()
    defer c.writeMu.Unlock()
    if c.plannerErr != nil { return 0, c.plannerErr }
    if len(b) == 0 { return 0, nil }
    if c.firstDone { return c.TCPConn.Write(b) }
    c.pending = append(c.pending, b...)
    if needsMoreFirstTLS(c.pending) {
        if c.pendingTimer == nil {
            c.pendingTimer = time.AfterFunc(firstTLSBufferTimeout, func() {
                c.writeMu.Lock()
                defer c.writeMu.Unlock()
                _ = c.flushFirstLocked()
            })
        }
        return len(b), nil
    }
    if err := c.flushFirstLocked(); err != nil { return 0, err }
    return len(b), nil
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
        // HTTP/1 Host can use the five original TCP strategies. A new TLS
        // record split candidate is meaningful only for TLS ClientHello.
        // Avoid selecting an HTTP no-op when both protocols share a host.
        var choice string
        var generation uint64
        if zapret2.IsTLSClientHelloPrefix(b) {
            key := c.host + "|" + c.TCPConn.RemoteAddr().(*net.TCPAddr).IP.String()
            choice, generation = zapret2Auto.chooseLive(key, adaptiveCandidates[:])
        } else {
            key := "http:" + c.host + "|" + c.TCPConn.RemoteAddr().(*net.TCPAddr).IP.String()
            choice, generation = zapret2Auto.chooseLive(key, adaptiveHTTPCandidates[:])
        }
        resolved, ok, err := parseDesyncTag(zapret2.TagPrefix + choice)
        if !ok || err != nil || resolved.kind == desyncAuto {
            c.plannerErr = fmt.Errorf("adaptive strategy selection rejected: %v", err)
            return 0, c.plannerErr
        }
        c.mode = resolved
        key := c.host + "|" + c.TCPConn.RemoteAddr().(*net.TCPAddr).IP.String()
        if !zapret2.IsTLSClientHelloPrefix(b) { key = "http:"+key }
        c.adaptiveSelection.Store(&adaptivePick{host: key, strategy: choice, generation: generation})
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
        // A TLS client may write an incomplete first record. Never modify
        // an incomplete TLS record or break a legitimate connection merely
        // because of its buffering. Reuse the existing first-byte TCP split
        // on this flow; it preserves all application bytes.
        if c.mode.kind == desyncTLSRecordSplit && zapret2.IsTLSClientHelloPrefix(b) {
            return c.splitFirstTLS(b)
        }
        desyncSkipped.Add(1)
        return c.TCPConn.Write(b)
    }
    if c.mode.kind == desyncTLSRecordSplit {
        if len(plan.Rewrite) != len(b)+5 || plan.Cut < 9 || plan.Cut >= len(plan.Rewrite)-5 {
            c.plannerErr = errors.New("invalid TLS-record splitting plan")
            return 0, c.plannerErr
        }
        return c.writeTLSRecordSplit(plan.Rewrite, plan.Cut, len(b))
    }
    if len(plan.Rewrite) != 0 {
        c.plannerErr = errors.New("unexpected TLS rewrite in non-TLS strategy")
        return 0, c.plannerErr
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
    case desyncSplit, desyncSplitSecond:
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
    case desyncSplitSecond: return zapret2.TagPrefix + "split-2"
    case desyncTLSRecordSplit: return zapret2.TagPrefix + "tlsrec-split"
    case desyncPass: return zapret2.TagPrefix + "pass"
    case desyncFake: return fmt.Sprintf("%sfake-%d", zapret2.TagPrefix, m.ttl)
    case desyncAuto: return zapret2.TagPrefix + "auto"
    }
    return zapret2.TagPrefix + "unsupported"
}


// writeTLSRecordSplit sends two valid TLS handshake records separately on the
// protected TCP socket, combining TLS-record and TCP-write fragmentation.
// If the first/second write fails, keep the failure sticky: retrying the
// original unsplit ClientHello on this connection could corrupt the stream.
// A successful write reports consumed *original* bytes, not the five added
// bytes of the second TLS record header.
func (c *desyncConn) writeTLSRecordSplit(payload []byte, cut, originalLen int) (int, error) {
    n, err := c.TCPConn.Write(payload[:cut])
    if err != nil || n != cut {
        if err == nil { err = errors.New("short first TLS record") }
        c.plannerErr = fmt.Errorf("Zapret2 TLS-record first write failed: %w", err)
        desyncSkipped.Add(1)
        return 0, c.plannerErr
    }
    time.Sleep(2 * time.Millisecond)
    n, err = c.TCPConn.Write(payload[cut:])
    if err != nil || n != len(payload)-cut {
        if err == nil { err = errors.New("short second TLS record") }
        c.plannerErr = fmt.Errorf("Zapret2 TLS-record second write failed: %w", err)
        desyncSkipped.Add(1)
        return 0, c.plannerErr
    }
    desyncApplied.Add(1)
    return originalLen, nil
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
    stageInitialSent atomic.Bool
    stageFirstReply atomic.Bool
    stageReadTimedOut atomic.Bool
    stageCloseRecorded atomic.Bool
}

func (c *desyncUDPConn) Read(b []byte) (int, error) {
    n, err := c.UDPConn.Read(b)
    if n > 0 {
        if c.stageInitialSent.Load() && c.stageFirstReply.CompareAndSwap(false, true) {
            zapret2Stage.udpFirstReply.Add(1)
            if pick := c.adaptiveSelection.Load(); pick != nil && pick.strategy == "pass" {
                zapret2Auto.retainPlainReply(pick.host, pick.generation)
            }
        }
        total := c.received.Add(int64(n))
        if total >= adaptivePayloadThreshold {
            if selected := c.adaptiveSelection.Load(); selected != nil {
                c.observed.Do(func() {
                    recordLocalSocketEvidence(selected, localdpi.SocketClose(total))
                })
            }
        }
    }
    if err != nil && c.stageInitialSent.Load() && !c.stageFirstReply.Load() &&
        isZapret2Timeout(err) && c.stageReadTimedOut.CompareAndSwap(false, true) &&
        c.received.Load()==0 {
        // A QUIC Initial was sent and timed out without even a UDP first
        // reply. This is weak reachability evidence, not proof of DPI.
        // Never infer an application response from packet send success.
        if pick:=c.adaptiveSelection.Load();pick!=nil {
            recordLocalSocketEvidence(pick, localdpi.SocketFirstReplyTimeout(true, false, 0))
        }
    }
    return n, err
}

func (c *desyncUDPConn) Close() error {
    if c.stageInitialSent.Load() && !c.stageFirstReply.Load() && c.stageCloseRecorded.CompareAndSwap(false, true) {
        zapret2Stage.udpClosedNoReply.Add(1)
    }
    c.observed.Do(func() {
        if pick := c.adaptiveSelection.Load(); pick != nil {
            // As with TCP, an ordinary zero-byte Close is not evidence
            // of a failed strategy; explicit read timeouts are handled above.
            total:=c.received.Load()
            recordLocalSocketEvidence(pick, localdpi.SocketClose(total))
        }
    })
    return c.UDPConn.Close()
}

const dummyQuicRepeats = 6

// Bound per-connection injection work. After the budget is exhausted we
// reject additional Initial retransmissions instead of quietly sending
// the initial handshake without its selected DPI strategy.
const maxQuicInitialFlights = 8

func (c *desyncUDPConn) Write(b []byte) (written int, writeErr error) {
    c.mu.Lock()
    defer c.mu.Unlock()
    initial := zapret2.IsQUICInitial(b)
    // A successful fake alone does not count. Require the genuine Initial.
    defer func() {
        if !initial { return }
        if writeErr != nil || written != len(b) {
            zapret2Stage.udpInitialFailed.Add(1)
        } else {
            c.stageInitialSent.Store(true)
            zapret2Stage.udpInitialSent.Add(1)
        }
    }()
    if c.plannerErr != nil { return 0, c.plannerErr }
    if (c.mode.kind == desyncAuto || zapret2Auto.wants(c.host)) && zapret2.IsQUICInitial(b) {
        // Apply one chosen TTL for this UDP flow, including retransmitted
        // Initials; no silent fallback to unmodified QUIC on injection error.
        if c.adaptiveSelection.Load() == nil {
            choice, generation := zapret2Auto.chooseLive("udp:"+c.host, adaptiveQuicCandidates[:])
            resolved, ok, err := parseDesyncTag(zapret2.TagPrefix + choice)
            if !ok || err != nil || resolved.kind != desyncFake && resolved.kind != desyncPass {
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
    if c.mode.kind == desyncPass && zapret2.IsQUICInitial(b) {
        // The explicit AUTO baseline sends real QUIC without malformed decoys.
        desyncSkipped.Add(1)
        return c.UDPConn.Write(b)
    }
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
