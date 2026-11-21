//go:build linux

package bridge

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

// clientHello — настоящий ClientHello crypto/tls с именем [name]: первая запись TLS.
func clientHello(t *testing.T, name string) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()
	go func() {
		_ = tls.Client(a, &tls.Config{ServerName: name, MinVersion: tls.VersionTLS12}).Handshake()
	}()
	head := make([]byte, 5)
	if _, err := io.ReadFull(b, head); err != nil {
		t.Fatal(err)
	}
	body := make([]byte, binary.BigEndian.Uint16(head[3:]))
	if _, err := io.ReadFull(b, body); err != nil {
		t.Fatal(err)
	}
	return append(head, body...)
}

func TestParseDesyncTag(t *testing.T) {
	for tag, want := range map[string]desyncMode{
		"dppass:exp-disorder": {kind: desyncDisorder, ttl: 1},
		"dppass:exp-split":    {kind: desyncSplit},
		"dppass:exp-fake-1":   {kind: desyncFake, ttl: 1},
		"dppass:exp-fake-8":   {kind: desyncFake, ttl: 8},
		"dppass:exp-fake-64":  {kind: desyncFake, ttl: 64},
	} {
		got, ok, err := parseDesyncTag(tag)
		if !ok || err != nil || got != want {
			t.Errorf("%s: %+v %v %v, нужно %+v", tag, got, ok, err, want)
		}
	}
	for _, tag := range []string{"proxy", "dppass:split", "direct"} {
		if _, ok, _ := parseDesyncTag(tag); ok {
			t.Errorf("%s — не эксперимент", tag)
		}
	}
	// Тег эксперимента с неверным видом — ошибка, а не тихое «как есть».
	for _, tag := range []string{"dppass:exp-fake-0", "dppass:exp-fake-65", "dppass:exp-fake-x", "dppass:exp-oob"} {
		if _, ok, err := parseDesyncTag(tag); !ok || err == nil {
			t.Errorf("%s: нужна ошибка", tag)
		}
	}
}

func TestSniRangeFindsTheNameInARealClientHello(t *testing.T) {
	for _, name := range []string{"a.example.com", "very-long-subdomain.of.example.org"} {
		hello := clientHello(t, name)
		s, e, ok := sniRange(hello)
		if !ok || string(hello[s:e]) != name {
			t.Fatalf("%s: %v %q", name, ok, hello[s:e])
		}
	}
	// Не ClientHello, обрезанная запись и запись без имени — «нет».
	hello := clientHello(t, "a.example.com")
	for name, b := range map[string][]byte{
		"HTTP":           []byte("GET / HTTP/1.1\r\nHost: a.example.com\r\n\r\n"),
		"обрезано":       hello[:60],
		"пусто":          nil,
		"не handshake":   append([]byte{23}, hello[1:]...),
		"не ClientHello": append(append([]byte{}, hello[:5]...), append([]byte{2}, hello[6:]...)...),
	} {
		if _, _, ok := sniRange(b); ok {
			t.Errorf("%s: имени быть не должно", name)
		}
	}
}

func TestSplitSendsValidClientHello(t *testing.T) {
	// Разделение должно сохранять байты TLS ClientHello, в отличие от fake TTL.
	hello := clientHello(t, "r1.googlevideo.com")
	ln, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil { t.Fatal(err) }
	defer ln.Close()
	client, err := net.DialTCP("tcp4", nil, ln.Addr().(*net.TCPAddr))
	if err != nil { t.Fatal(err) }
	defer client.Close()
	server, err := ln.AcceptTCP()
	if err != nil { t.Fatal(err) }
	defer server.Close()
	conn := &desyncConn{TCPConn: client, mode: desyncMode{kind: desyncSplit}}
	before, _ := DesyncStats()
	if n, err := conn.Write(hello); err != nil || n != len(hello) { t.Fatalf("split write: %d %v", n, err) }
	got := make([]byte, len(hello))
	_ = server.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(server, got); err != nil { t.Fatal(err) }
	if !bytes.Equal(got, hello) { t.Fatal("split corrupted TLS ClientHello") }
	after, _ := DesyncStats()
	if after <= before { t.Fatal("split was not applied") }
}

func TestFakeChunkReplacesOnlyTheName(t *testing.T) {
	hello := clientHello(t, "a.example.com")
	s, e, _ := sniRange(hello)
	fake := fakeChunk(hello, s, e)
	if len(fake) != len(hello) || !bytes.Equal(fake[:s], hello[:s]) || !bytes.Equal(fake[e:], hello[e:]) {
		t.Fatal("подделка меняет не только имя")
	}
	if bytes.Equal(fake[s:e], hello[s:e]) {
		t.Fatal("имя не заменено")
	}
	for _, c := range fake[s:e] {
		if c < 'a' || c > 'z' {
			t.Fatalf("в подложном имени %q", fake[s:e])
		}
	}
}

// Обёртка набирателя оборачивает только исходящие эксперимента и не трогает остальные (D-116).
func TestDesyncDialerWrapsOnlyExperimentOutbounds(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	// Стандартный набиратель применяет хук защиты (D-25), если его уже поставил
	// другой тест: защитник, который пускает, и учёт — сокет прошёл через хук.
	if err := installHook(); err != nil {
		t.Fatal(err)
	}
	rec := &recorder{allow: true, fds: make(chan int, 16)}
	setGuard(rec)
	t.Cleanup(func() { setGuard(denyAll{}) })
	d := &desyncDialer{base: &internet.DefaultSystemDialer{}}
	port := ln.Addr().(*net.TCPAddr).Port
	dest := xnet.TCPDestination(xnet.LocalHostIP, xnet.Port(port))
	dial := func(tag string) net.Conn {
		ctx := session.ContextWithOutbounds(context.Background(), []*session.Outbound{{Tag: "proxy"}, {Tag: tag}})
		c, err := d.Dial(ctx, nil, dest, nil)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c
	}
	if _, ok := dial("dppass:split").(*desyncConn); ok {
		t.Error("разбиение D-68 — не эксперимент")
	}
	if c, ok := dial("dppass:exp-fake-5").(*desyncConn); !ok || c.mode.ttl != 5 {
		t.Error("исходящий эксперимента не обёрнут")
	}
	_, skipped := DesyncStats()
	if _, ok := dial("dppass:exp-fake-99").(*desyncConn); ok {
		t.Error("неверный тег — как есть")
	}
	if _, s := DesyncStats(); s != skipped+1 {
		t.Error("неверный тег не засчитан пропуском")
	}
	if n := len(rec.fds); n != 3 {
		t.Errorf("защитник видел %d сокетов из 3: обёртка обошла хук защиты", n)
	}
}


func TestHttpHostAndQuicInitialRecognized(t *testing.T) {
	http := []byte("GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n")
	start, end, ok := firstHostRange(http)
	if !ok || string(http[start:end]) != "example.com" {
		t.Fatalf("http host: %v %q", ok, http[start:end])
	}
	for _, sample := range [][]byte{
		[]byte("GET / HTTP/1.1\r\nHost: exam"),
		[]byte("not http\r\nHost: example.com\r\n\r\n"),
		[]byte("GET / HTTP/1.1\r\nHost: \r\n\r\n"),
	} {
		if _, _, ok := firstHostRange(sample); ok {
			t.Fatalf("unexpected host in %q", sample)
		}
	}
	initial := make([]byte, 1200)
	initial[0], initial[4] = 0xc0, 1
	if !isQUICInitial(initial) {
		t.Fatal("QUIC v1 Initial not recognized")
	}
	initial[0] = 0xd0
	if isQUICInitial(initial) {
		t.Fatal("QUIC v1 handshake is not Initial")
	}
	initial[0], initial[1], initial[2], initial[3], initial[4] = 0xd0, 0x6b, 0x33, 0x43, 0xcf
	if !isQUICInitial(initial) {
		t.Fatal("QUIC v2 Initial not recognized")
	}
}

func TestUDPFirstQUICWriteSendsDummyBeforeReal(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127,0,0,1)})
	if err != nil { t.Fatal(err) }
	defer receiver.Close()
	client, err := net.DialUDP("udp4", nil, receiver.LocalAddr().(*net.UDPAddr))
	if err != nil { t.Fatal(err) }
	defer client.Close()
	conn := &desyncUDPConn{UDPConn: client, mode: desyncMode{kind: desyncFake, ttl: 1}}
	initial := make([]byte, 1200)
	initial[0], initial[4] = 0xc0, 1
	if n, err := conn.Write(initial); err != nil || n != len(initial) {
		t.Fatalf("first write: %d %v", n, err)
	}
	buf := make([]byte, 1400)
	_ = receiver.SetReadDeadline(time.Now().Add(3 * time.Second))
	for i:=0;i<dummyQuicRepeats;i++ {
		n, _, e := receiver.ReadFromUDP(buf)
		if e!=nil { t.Fatalf("fake %d: %v", i,e) }
		if n!=620 || buf[0]!=0x40 { t.Fatalf("fake %d: size %d first %x",i,n,buf[0]) }
	}
	n, _, e := receiver.ReadFromUDP(buf)
	if e != nil || n != 1200 || buf[0] != 0xc0 { t.Fatalf("real: size=%d %v",n,e) }
}

// ---- Стенд (FAKE_PACKETS.md, §6.1) ----
//
// Три сетевых пространства имён: клиент — маршрутизатор — сервер, пары
// veth. Маршрутизатор пересылает и уменьшает TTL; на его входе со стороны
// клиента — запись того, что прошло (сокет AF_PACKET): модель фильтра на
// первом узле. Нужны root и iproute2.

const (
	standClient = "dpt-desync-c"
	standRouter = "dpt-desync-r"
	standServer = "dpt-desync-s"
	clientIP    = "10.77.1.2"
	serverIP    = "10.77.2.2"
	standPort   = 4433
	defaultTTL  = 64
)

func standOrSkip(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("стенд D-116: нужен root — свои сетевые пространства имён")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("стенд D-116: нужен iproute2 (ip)")
	}
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v\n%s", args, err, out)
		}
	}
	for _, ns := range []string{standClient, standRouter, standServer} {
		_ = exec.Command("ip", "netns", "del", ns).Run()
		ip("netns", "add", ns)
		ns := ns
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
	}
	ip("link", "add", "c0", "netns", standClient, "type", "veth", "peer", "name", "r0", "netns", standRouter)
	ip("link", "add", "s0", "netns", standServer, "type", "veth", "peer", "name", "r1", "netns", standRouter)
	ip("-n", standClient, "addr", "add", clientIP+"/24", "dev", "c0")
	ip("-n", standRouter, "addr", "add", "10.77.1.1/24", "dev", "r0")
	ip("-n", standRouter, "addr", "add", "10.77.2.1/24", "dev", "r1")
	ip("-n", standServer, "addr", "add", serverIP+"/24", "dev", "s0")
	for ns, links := range map[string][]string{standClient: {"lo", "c0"}, standRouter: {"lo", "r0", "r1"}, standServer: {"lo", "s0"}} {
		for _, l := range links {
			ip("-n", ns, "link", "set", l, "up")
		}
	}
	ip("-n", standClient, "route", "add", "default", "via", "10.77.1.1")
	ip("-n", standServer, "route", "add", "default", "via", "10.77.2.1")
	if out, err := exec.Command("ip", "netns", "exec", standRouter, "sysctl", "-qw", "net.ipv4.ip_forward=1").CombinedOutput(); err != nil {
		t.Fatalf("пересылка на маршрутизаторе: %v\n%s", err, out)
	}
}

// inNetns выполняет fn на своём потоке ОС в пространстве имён [ns]. Поток
// не возвращается в пул: горутина кончается, не сняв привязку, и Go его
// завершает.
func inNetns(ns string, fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		f, err := os.Open("/run/netns/" + ns)
		if err != nil {
			errc <- err
			return
		}
		defer f.Close()
		if err := unix.Setns(int(f.Fd()), unix.CLONE_NEWNET); err != nil {
			errc <- err
			return
		}
		errc <- fn()
	}()
	return <-errc
}

// seg — сегмент TCP от клиента, увиденный маршрутизатором.
type seg struct {
	ttl     int
	seq     uint32
	payload []byte
}

// capture пишет сегменты с данными от клиента на входе маршрутизатора, пока не закрыт stop.
func capture(t *testing.T) (segs func() []seg, stop func()) {
	t.Helper()
	var fd int
	if err := inNetns(standRouter, func() error {
		ifi, err := net.InterfaceByName("r0")
		if err != nil {
			return err
		}
		fd, err = unix.Socket(unix.AF_PACKET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, int(htons(unix.ETH_P_IP)))
		if err != nil {
			return err
		}
		if err := unix.Bind(fd, &unix.SockaddrLinklayer{Protocol: htons(unix.ETH_P_IP), Ifindex: ifi.Index}); err != nil {
			return err
		}
		tv := unix.NsecToTimeval((100 * time.Millisecond).Nanoseconds())
		return unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	}); err != nil {
		t.Fatalf("запись на маршрутизаторе: %v", err)
	}
	out := make(chan []seg, 1)
	done := make(chan struct{})
	go func() {
		var got []seg
		buf := make([]byte, 65536)
		for {
			select {
			case <-done:
				out <- got
				return
			default:
			}
			n, _, err := unix.Recvfrom(fd, buf, 0)
			if err != nil {
				continue
			}
			p := buf[:n]
			if len(p) < 20 || p[9] != unix.IPPROTO_TCP || net.IP(p[12:16]).String() != clientIP {
				continue
			}
			ihl := int(p[0]&0x0f) * 4
			tcp := p[ihl:]
			off := int(tcp[12]>>4) * 4
			if len(tcp) <= off {
				continue
			}
			got = append(got, seg{ttl: int(p[8]), seq: binary.BigEndian.Uint32(tcp[4:]), payload: append([]byte(nil), tcp[off:]...)})
		}
	}()
	var result []seg
	stopped := false
	stop = func() {
		if stopped {
			return
		}
		stopped = true
		close(done)
		result = <-out
		unix.Close(fd)
	}
	t.Cleanup(stop)
	return func() []seg { stop(); return result }, stop
}

// standRun — клиент шлёт [hello] через desyncConn с [mode]; что получил сервер и что видел маршрутизатор.
func standRun(t *testing.T, mode desyncMode, hello []byte) (received []byte, segs []seg, elapsed time.Duration) {
	t.Helper()
	var ln net.Listener
	if err := inNetns(standServer, func() (err error) {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", serverIP, standPort))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(10 * time.Second))
		b := make([]byte, len(hello))
		n, _ := io.ReadFull(c, b)
		got <- b[:n]
		_, _ = c.Write([]byte{1})
	}()
	segsOf, _ := capture(t)
	var conn *net.TCPConn
	if err := inNetns(standClient, func() error {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", serverIP, standPort), 5*time.Second)
		if err != nil {
			return err
		}
		conn = c.(*net.TCPConn)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	dc := &desyncConn{TCPConn: conn, mode: mode}
	started := time.Now()
	if _, err := dc.Write(hello); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	ack := make([]byte, 1)
	if _, err := io.ReadFull(conn, ack); err != nil && !errors.Is(err, io.EOF) {
		t.Fatalf("ответ сервера: %v", err)
	}
	elapsed = time.Since(started)
	received = <-got
	// Повторы ядра ОС уже прошли (сервер всё принял); запись — до закрытия.
	time.Sleep(50 * time.Millisecond)
	return received, segsOf(), elapsed
}

func TestStandFakeDiesOnTheFirstHopAndServerGetsRealBytes(t *testing.T) {
	standOrSkip(t)
	hello := clientHello(t, "a.example.com")
	s, e, _ := sniRange(hello)
	applied, _ := DesyncStats()
	received, segs, elapsed := standRun(t, desyncMode{kind: desyncFake, ttl: 1}, hello)
	if !bytes.Equal(received, hello) {
		t.Fatalf("сервер получил не настоящие байты: имя %q", received[s:e])
	}
	if a, _ := DesyncStats(); a != applied+1 {
		t.Error("приём не засчитан")
	}
	if len(segs) < 2 {
		t.Fatalf("маршрутизатор видел %d сегментов", len(segs))
	}
	first := segs[0]
	if first.ttl != 1 || bytes.Equal(first.payload, hello[:len(first.payload)]) {
		t.Fatalf("первым должна пройти подделка с TTL 1: TTL %d", first.ttl)
	}
	if len(first.payload) < e-s || !bytes.Contains(first.payload, hello[:s]) {
		t.Fatalf("подделка — не начало ClientHello: %d байт", len(first.payload))
	}
	// Тот же номер последовательности позже — настоящие байты с обычным TTL: TTL вернулся.
	var real *seg
	for i := range segs[1:] {
		if segs[1+i].seq == first.seq {
			real = &segs[1+i]
			break
		}
	}
	if real == nil || real.ttl != defaultTTL || !bytes.Equal(real.payload[:len(first.payload)], hello[:len(first.payload)]) {
		t.Fatalf("повтор с настоящими байтами и TTL %d не найден", defaultTTL)
	}
	for _, sg := range segs[1:] {
		if sg.ttl != defaultTTL {
			t.Fatalf("после подделки TTL не вернулся: %d", sg.ttl)
		}
	}
	t.Logf("подделка TTL 1: %d сегментов, ответ сервера через %v", len(segs), elapsed)
}

func TestStandDisorderSendsTheStartWithTTL1First(t *testing.T) {
	standOrSkip(t)
	hello := clientHello(t, "a.example.com")
	s, e, _ := sniRange(hello)
	cut := s + (e-s)/2
	received, segs, elapsed := standRun(t, desyncMode{kind: desyncDisorder, ttl: 1}, hello)
	if !bytes.Equal(received, hello) {
		t.Fatal("сервер получил не те байты")
	}
	if len(segs) < 3 || segs[0].ttl != 1 || len(segs[0].payload) != cut {
		t.Fatalf("первой — начало до середины имени с TTL 1: %d сегментов, TTL %d", len(segs), segs[0].ttl)
	}
	if segs[1].ttl != defaultTTL || segs[1].seq != segs[0].seq+uint32(cut) {
		t.Fatal("вторым — остаток с обычным TTL")
	}
	retransmitted := false
	for _, sg := range segs[2:] {
		retransmitted = retransmitted || (sg.seq == segs[0].seq && sg.ttl == defaultTTL)
	}
	if !retransmitted {
		t.Fatal("начало не повторено ядром ОС с обычным TTL")
	}
	t.Logf("перестановка: %d сегментов, ответ сервера через %v", len(segs), elapsed)
}

// Отрицательный случай: TTL подделки больше расстояния до сервера — подделка
// дошла, и сервер получил подложное имя (так неверный TTL рвёт соединение).
func TestStandFakeWithTooLargeTTLReachesTheServer(t *testing.T) {
	standOrSkip(t)
	hello := clientHello(t, "a.example.com")
	s, e, _ := sniRange(hello)
	received, _, _ := standRun(t, desyncMode{kind: desyncFake, ttl: 2}, hello)
	if len(received) < e || bytes.Equal(received[s:e], hello[s:e]) {
		t.Fatal("подделка с TTL 2 должна дойти до сервера через один узел")
	}
}

func htons(v uint16) uint16 { return v<<8 | v>>8 }
