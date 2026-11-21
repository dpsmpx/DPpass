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
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
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

// parseDesyncTag — вид приёма по тегу исходящего; ok — тег эксперимента.
func parseDesyncTag(tag string) (desyncMode, bool, error) {
	rest, ok := strings.CutPrefix(tag, expTagPrefix)
	if !ok {
		return desyncMode{}, false, nil
	}
	if rest == "disorder" {
		return desyncMode{kind: desyncDisorder, ttl: 1}, true, nil
	}
	if rest == "split" {
		return desyncMode{kind: desyncSplit}, true, nil
	}
	if v, ok := strings.CutPrefix(rest, "fake-"); ok {
		ttl, err := strconv.Atoi(v)
		if err != nil || ttl < minFakeTTL || ttl > maxFakeTTL {
			return desyncMode{}, true, fmt.Errorf("TTL подделки %q — не число %d…%d", v, minFakeTTL, maxFakeTTL)
		}
		return desyncMode{kind: desyncFake, ttl: ttl}, true, nil
	}
	return desyncMode{}, true, fmt.Errorf("вид приёма %q не известен", rest)
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
		desyncSkipped.Add(1)
		return conn, nil
	}
	if dest.Network == xnet.Network_TCP {
		tcp, isTCP := conn.(*net.TCPConn)
		if !isTCP {
			desyncSkipped.Add(1)
			return conn, nil
		}
		return &desyncConn{TCPConn: tcp, mode: mode}, nil
	}
	udp, isUDP := conn.(*net.UDPConn)
	if !isUDP {
		desyncSkipped.Add(1)
		return conn, nil
	}
	return &desyncUDPConn{UDPConn: udp, mode: mode}, nil
}

func (d *desyncDialer) DestIpAddress() net.IP { return d.base.DestIpAddress() }

// desyncConn — соединение эксперимента: приём — только на первой записи.
type desyncConn struct {
	*net.TCPConn
	mode  desyncMode
	first sync.Once
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
	return c.TCPConn.Write(b)
}

// desyncFirst — первая запись с приёмом; не вышло до отправки хоть байта —
// запись как есть.
func (c *desyncConn) desyncFirst(b []byte) (int, error) {
	start, end, ok := firstHostRange(b)
	if !ok {
		desyncSkipped.Add(1)
		return c.TCPConn.Write(b)
	}
	cut := start + (end-start)/2
	var sent int
	var err error
	switch c.mode.kind {
	case desyncDisorder:
		sent, err = c.lowTTLWrite(b[:cut])
	case desyncFake:
		sent, err = c.fakeWrite(b[:cut], fakeChunk(b[:cut], start, end))
	case desyncSplit:
		// Две записи на TCP-сокет с TCP_NODELAY по умолчанию в Go.
		// Без поддельных байтов: безопасный вариант multisplit для сетей,
		// где малый TTL ломает соединение или не помогает.
		sent, err = c.TCPConn.Write(b[:cut])
	}
	if sent == 0 && err != nil {
		// Ничего не ушло: приём не удался до отправки — как есть.
		desyncSkipped.Add(1)
		return c.TCPConn.Write(b)
	}
	if err != nil {
		return sent, err
	}
	desyncApplied.Add(1)
	m, err := c.TCPConn.Write(b[cut:])
	return sent + m, err
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

// desyncUDPConn sends a low-TTL dummy QUIC datagram *before* the actual first
// Initial. This works without raw sockets, but is not equivalent to nfqws2's
// packet-level engine; it is an opt-in best-effort UDP counterpart to the
// existing TCP experiment. The real Initial is always sent unmodified and
// with the original TTL. No extra packet is sent outside the QUIC Initial case.
type desyncUDPConn struct {
	*net.UDPConn
	mode desyncMode
	mu sync.Mutex
	first bool
}

const dummyQuicRepeats = 6

func (c *desyncUDPConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.first {
		c.first = true
		if c.mode.kind == desyncFake && isQUICInitial(b) {
			c.sendLowTTLDummyQUIC()
		} else {
			desyncSkipped.Add(1)
		}
	}
	return c.UDPConn.Write(b)
}

func (c *desyncUDPConn) sendLowTTLDummyQUIC() {
	rc, err := c.SyscallConn()
	if err != nil {
		desyncSkipped.Add(1)
		return
	}
	v6 := false
	if a, ok := c.RemoteAddr().(*net.UDPAddr); ok {
		v6 = a.IP.To4() == nil
	}
	// A deliberately non-Initial 620-byte dummy payload, same as the
	// upstream nfqws2 fake_default_quic blob. Keep it below MTU.
	fake := make([]byte, 620)
	fake[0] = 0x40
	restore, err := setTTL(rc, v6, c.mode.ttl)
	if err != nil {
		desyncSkipped.Add(1)
		return
	}
	allSent := true
	for i := 0; i < dummyQuicRepeats; i++ {
		if n, e := c.UDPConn.Write(fake); e != nil || n != len(fake) {
			allSent = false
			break
		}
	}
	if err := restore(); err != nil {
		allSent = false
	}
	if allSent {
		desyncApplied.Add(1)
	} else {
		desyncSkipped.Add(1)
	}
}

// Minimal QUIC v1/v2 long-header Initial recognizer. Packet length >= 1200
// (RFC 9000) guards against DNS or other random UDP, and the version/type
// check avoids injecting the dummy on unsupported long-header variants.
func isQUICInitial(b []byte) bool {
	if len(b) < 1200 || b[0]&0xc0 != 0xc0 {
		return false
	}
	version := binary.BigEndian.Uint32(b[1:5])
	kind := (b[0] >> 4) & 3
	return (version == 0x00000001 && kind == 0) ||
		(version == 0x6b3343cf && kind == 1)
}

// firstHostRange accepts TLS SNI or an HTTP/1.x Host header.
func firstHostRange(b []byte) (start, end int, ok bool) {
	if s, e, yes := sniRange(b); yes {
		return s, e, true
	}
	return httpHostRange(b)
}

// Host header is only recognized in a complete HTTP/1.x request, avoiding
// accidental manipulation of arbitrary TCP streams or partial headers.
func httpHostRange(b []byte) (start, end int, ok bool) {
	if len(b) < 22 || len(b) > 16*1024 {
		return 0, 0, false
	}
	firstLine := bytes.Index(b, []byte("\r\n"))
	headersEnd := bytes.Index(b, []byte("\r\n\r\n"))
	if firstLine <= 0 || headersEnd <= firstLine || !bytes.Contains(b[:firstLine], []byte(" HTTP/1.")) {
		return 0, 0, false
	}
	method := b[:firstLine]
	valid := false
	for _, m := range [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("PATCH "), []byte("DELETE "), []byte("OPTIONS ")} {
		if bytes.HasPrefix(method, m) {
			valid = true
			break
		}
	}
	if !valid {
		return 0, 0, false
	}
	for p := firstLine + 2; p < headersEnd; {
		rel := bytes.Index(b[p:headersEnd+2], []byte("\r\n"))
		if rel < 0 { return 0, 0, false }
		lineEnd := p + rel
		colon := bytes.IndexByte(b[p:lineEnd], ':')
		if colon > 0 && bytes.EqualFold(b[p:p+colon], []byte("Host")) {
			a := p + colon + 1
			for a < lineEnd && (b[a] == ' ' || b[a] == '\t') { a++ }
			e := lineEnd
			for e > a && (b[e-1] == ' ' || b[e-1] == '\t') { e-- }
			if e-a == 0 || e-a > 255 || bytes.IndexAny(b[a:e], " \t\r\n") >= 0 {
				return 0, 0, false
			}
			return a, e, true
		}
		p = lineEnd + 2
	}
	return 0, 0, false
}

// fakeChunk — подложная часть: те же байты, имя в [start, end) заменено
// случайными строчными буквами той же длины. Имя — не чужой домен:
// сочетание букв без смысла (FAKE_PACKETS.md, §5, «Подложное имя»).
func fakeChunk(part []byte, start, end int) []byte {
	fake := append([]byte(nil), part...)
	if end > len(fake) {
		end = len(fake)
	}
	if start >= end {
		return fake
	}
	letters := make([]byte, end-start)
	if _, err := rand.Read(letters); err != nil {
		for i := range letters {
			letters[i] = 'x'
		}
	}
	for i, r := range letters {
		fake[start+i] = 'a' + r%26
	}
	return fake
}

// sniRange — где в записи TLS лежит имя сервера (server_name): [start, end)
// байтов имени. ok — это начало ClientHello, и имя целиком в [b].
func sniRange(b []byte) (start, end int, ok bool) {
	// Запись TLS: тип 22 (handshake), версия, длина; затем сообщение 1 (ClientHello).
	if len(b) < 5+4 || b[0] != 22 || b[5] != 1 {
		return 0, 0, false
	}
	p := 5 + 4 // заголовок записи и сообщения
	p += 2 + 32 // версия и случайное
	if p+1 > len(b) {
		return 0, 0, false
	}
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return 0, 0, false
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // наборы шифров
	if p+1 > len(b) {
		return 0, 0, false
	}
	p += 1 + int(b[p]) // методы сжатия
	if p+2 > len(b) {
		return 0, 0, false
	}
	extEnd := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	if extEnd > len(b) {
		extEnd = len(b)
	}
	for p+4 <= extEnd {
		typ := binary.BigEndian.Uint16(b[p:])
		size := int(binary.BigEndian.Uint16(b[p+2:]))
		body := p + 4
		if body+size > len(b) {
			return 0, 0, false
		}
		if typ == 0 { // server_name: список, первый — host_name
			if size < 5 || b[body+2] != 0 {
				return 0, 0, false
			}
			n := int(binary.BigEndian.Uint16(b[body+3:]))
			s := body + 5
			if n == 0 || s+n > body+size {
				return 0, 0, false
			}
			return s, s + n, true
		}
		p = body + size
	}
	return 0, 0, false
}
