package bridge

import (
	"context"
	"io"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xtls/xray-core/app/dispatcher"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/serial"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/dns"
	"github.com/xtls/xray-core/features/outbound"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/transport"
)

// Учёт соединений ядра (D-106): анализатор видит каждое соединение, которое
// ядро ведёт, — откуда, куда, имя сайта после распознавания, маршрут
// (исходящий), байты и порции данных в обе стороны, время до первого байта
// ответа, простой и итог. Исходники Xray не меняются: вместо диспетчера ядра
// (`app.dispatcher.Config`) мост ставит свою обёртку над тем же
// `dispatcher.DefaultDispatcher` (маркер — `dispatcher.SessionConfig`,
// для которого у Xray своей фабрики нет). Выключен учёт — обёртка лишь
// передаёт вызов: одна атомарная проверка на соединение.
//
// Данные — только в памяти моста: открытые и закрытые за последние
// [connRetain]. На диск мост ничего не пишет; что хранить дольше, решает
// приложение (журнал уникальных соединений, D-106).

const (
	// Закрытые соединения видны столько после закрытия.
	connRetain = 5 * time.Minute
	// Больше закрытых не держим: старые уходят первыми.
	connMaxClosed = 2000
	// Больше открытых не учитываем: новые идут без учёта, их число — в снимке.
	connMaxLive = 4096
)

// Состояние соединения в снимке; буквы — договор с engine.xray.XrayJni.decodeConnections (Kotlin).
const (
	connOpen   = "o" // открыто
	connClosed = "c" // закрыто без ошибки
	connFailed = "e" // прервано: исходящий не открылся или оборвался
)

type connTracker struct {
	enabled atomic.Bool
	nextID  atomic.Uint64
	now     func() time.Time

	mu      sync.Mutex
	live    map[uint64]*trackedConn
	closed  []*trackedConn // по времени закрытия, старые впереди
	skipped uint64         // не учтены: открытых больше connMaxLive
}

var tracker = newConnTracker(time.Now)

func newConnTracker(now func() time.Time) *connTracker {
	return &connTracker{now: now, live: map[uint64]*trackedConn{}}
}

type trackedConn struct {
	t       *connTracker
	id      uint64
	network string
	inbound string
	source  string
	target  string
	start   time.Time

	// Под t.mu.
	domain   string
	protocol string
	route    string
	end      time.Time
	state    string

	up, down, upChunks, downChunks atomic.Int64
	firstDown, lastActive          atomic.Int64 // UnixNano; 0 — ещё не было
	captured                       atomic.Bool
	finished                       sync.Once

	ob      *session.Outbound
	content *session.Content
}

// SetConnTracking включает и выключает учёт. Выключение стирает учтённое:
// адреса назначения — чувствительные данные (T3), и держать их, когда
// пользователь анализатор выключил, незачем.
func SetConnTracking(on bool) {
	tracker.setEnabled(on)
}

func (t *connTracker) setEnabled(on bool) {
	t.enabled.Store(on)
	if !on {
		t.mu.Lock()
		t.live = map[uint64]*trackedConn{}
		t.closed = nil
		t.skipped = 0
		t.mu.Unlock()
	}
}

// open — новое соединение; nil — учёт выключен или открытых слишком много.
func (t *connTracker) open(ctx context.Context, dest xnet.Destination) (context.Context, *trackedConn) {
	if !t.enabled.Load() {
		return ctx, nil
	}
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		outbounds = []*session.Outbound{{}}
		ctx = session.ContextWithOutbounds(ctx, outbounds)
	}
	content := session.ContentFromContext(ctx)
	if content == nil {
		content = new(session.Content)
		ctx = session.ContextWithContent(ctx, content)
	}
	c := &trackedConn{
		t:       t,
		id:      t.nextID.Add(1),
		network: dest.Network.SystemString(),
		target:  dest.NetAddr(),
		start:   t.now(),
		state:   connOpen,
		ob:      outbounds[len(outbounds)-1],
		content: content,
	}
	if in := session.InboundFromContext(ctx); in != nil {
		c.inbound = in.Tag
		if in.Source.IsValid() {
			c.source = in.Source.NetAddr()
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if len(t.live) >= connMaxLive {
		t.skipped++
		return ctx, nil
	}
	t.live[c.id] = c
	return ctx, c
}

// capture — маршрут и распознанное имя из сессии ядра. Вызывается только
// там, где запись этих полей диспетчером уже видна этой горутине: после
// возврата DispatchLink и на первых данных ответа (их пишет исходящий,
// запущенный после выбора маршрута).
func (c *trackedConn) capture() {
	if c.captured.Swap(true) {
		return
	}
	route, domain := c.ob.Tag, ""
	if c.ob.RouteTarget.IsValid() && c.ob.RouteTarget.Address.Family().IsDomain() {
		domain = c.ob.RouteTarget.Address.Domain()
	} else if c.ob.Target.IsValid() && c.ob.Target.Address.Family().IsDomain() {
		domain = c.ob.Target.Address.Domain()
	}
	protocol := c.content.Protocol
	c.t.mu.Lock()
	c.route, c.domain, c.protocol = route, domain, protocol
	c.t.mu.Unlock()
}

func (c *trackedConn) count(up bool, mb buf.MultiBuffer) {
	if mb.IsEmpty() {
		return
	}
	now := c.t.now().UnixNano()
	n := int64(mb.Len())
	if up {
		c.up.Add(n)
		c.upChunks.Add(int64(len(mb)))
	} else {
		c.down.Add(n)
		c.downChunks.Add(int64(len(mb)))
		c.firstDown.CompareAndSwap(0, now)
	}
	c.lastActive.Store(now)
}

// finish — соединение закрыто; failed — прервано, а не закрыто штатно.
func (c *trackedConn) finish(failed bool) {
	c.finished.Do(func() {
		t := c.t
		t.mu.Lock()
		defer t.mu.Unlock()
		c.end = t.now()
		c.state = connClosed
		if failed {
			c.state = connFailed
		}
		delete(t.live, c.id)
		t.closed = append(t.closed, c)
		if over := len(t.closed) - connMaxClosed; over > 0 {
			t.closed = append([]*trackedConn(nil), t.closed[over:]...)
		}
	})
}

// trackingDispatcher — диспетчер ядра с учётом соединений.
type trackingDispatcher struct {
	inner *dispatcher.DefaultDispatcher
}

func init() {
	// Маркер обёртки — сообщение, у которого в Xray нет своей фабрики.
	common.Must(common.RegisterConfig((*dispatcher.SessionConfig)(nil), func(ctx context.Context, _ interface{}) (interface{}, error) {
		d := new(dispatcher.DefaultDispatcher)
		// Те же зависимости, что у фабрики Xray: и порядок готовности тот же.
		if err := core.RequireFeatures(ctx, func(om outbound.Manager, router routing.Router, pm policy.Manager, sm stats.Manager, _ dns.Client) error {
			return d.Init(&dispatcher.Config{}, om, router, pm, sm)
		}); err != nil {
			return nil, err
		}
		return &trackingDispatcher{inner: d}, nil
	}))
}

// withConnTracking ставит обёртку вместо диспетчера ядра. Политика моста
// проверила конфигурацию до этого: заменяется только `app.dispatcher.Config`.
func withConnTracking(cfg *core.Config) *core.Config {
	for i, app := range cfg.App {
		if app.Type == serial.GetMessageType(&dispatcher.Config{}) {
			cfg.App[i] = serial.ToTypedMessage(&dispatcher.SessionConfig{})
		}
	}
	return cfg
}

func (*trackingDispatcher) Type() interface{} { return routing.DispatcherType() }

func (d *trackingDispatcher) Start() error { return d.inner.Start() }

func (d *trackingDispatcher) Close() error { return d.inner.Close() }

// Dispatch — входы прокси (раздача, без VPN): ядро отдаёт входу свою пару
// каналов; учёт — на стороне входа: запись — к серверу, чтение — ответ.
func (d *trackingDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	ctx, c := tracker.open(ctx, dest)
	link, err := d.inner.Dispatch(ctx, dest)
	if c == nil {
		return link, err
	}
	if err != nil {
		c.finish(true)
		return link, err
	}
	return &transport.Link{
		Reader: &countingReader{Reader: link.Reader, c: c, up: false, ends: true},
		Writer: &countingWriter{Writer: link.Writer, c: c, up: true, owned: true},
	}, nil
}

// DispatchLink — вход TUN и тестовый вход: каналы входа ядро передаёт
// исходящему; чтение — от программы к серверу, запись — ответ.
func (d *trackingDispatcher) DispatchLink(ctx context.Context, dest xnet.Destination, link *transport.Link) error {
	ctx, c := tracker.open(ctx, dest)
	if c == nil {
		return d.inner.DispatchLink(ctx, dest, link)
	}
	w := &countingWriter{Writer: link.Writer, c: c, up: false, ends: true}
	err := d.inner.DispatchLink(ctx, dest, &transport.Link{
		Reader: &countingReader{Reader: link.Reader, c: c, up: true},
		Writer: w,
	})
	// DispatchLink возвращается, когда исходящий закончил: маршрут виден этой горутине.
	c.capture()
	c.finish(err != nil || w.interrupted.Load())
	return err
}

type countingReader struct {
	buf.Reader
	c    *trackedConn
	up   bool
	ends bool // ответ: ошибка чтения — конец соединения (Dispatch)
}

func (r *countingReader) ReadMultiBuffer() (buf.MultiBuffer, error) {
	mb, err := r.Reader.ReadMultiBuffer()
	r.after(mb, err)
	return mb, err
}

// ReadMultiBufferTimeout — распознавание сайта ждёт данные с тайм-аутом.
func (r *countingReader) ReadMultiBufferTimeout(d time.Duration) (buf.MultiBuffer, error) {
	tr, ok := r.Reader.(buf.TimeoutReader)
	if !ok {
		return r.ReadMultiBuffer()
	}
	mb, err := tr.ReadMultiBufferTimeout(d)
	if err == buf.ErrReadTimeout {
		return mb, err
	}
	r.after(mb, err)
	return mb, err
}

func (r *countingReader) after(mb buf.MultiBuffer, err error) {
	r.c.count(r.up, mb)
	if !r.up && !mb.IsEmpty() {
		r.c.capture()
	}
	if r.ends && err != nil {
		r.c.finish(err != io.EOF)
	}
}

func (r *countingReader) Interrupt() {
	common.Interrupt(r.Reader)
	if r.ends {
		r.c.finish(true)
	}
}

func (r *countingReader) Close() error { return common.Close(r.Reader) }

type countingWriter struct {
	buf.Writer
	c    *trackedConn
	up   bool
	ends bool // ответ (DispatchLink): Interrupt — исходящий оборвался
	// Запрос (Dispatch): канал держит вход, и его Close или Interrupt — конец
	// соединения. Вход простого HTTP закрывает канал, дочитав ответ, но не
	// до конца потока: без этого соединение осталось бы открытым навсегда.
	owned       bool
	interrupted atomic.Bool
}

func (w *countingWriter) WriteMultiBuffer(mb buf.MultiBuffer) error {
	w.c.count(w.up, mb)
	if !w.up && !mb.IsEmpty() {
		w.c.capture()
	}
	return w.Writer.WriteMultiBuffer(mb)
}

func (w *countingWriter) Interrupt() {
	if w.ends {
		w.interrupted.Store(true)
	}
	common.Interrupt(w.Writer)
	if w.owned {
		w.c.finish(true)
	}
}

func (w *countingWriter) Close() error {
	err := common.Close(w.Writer)
	if w.owned {
		w.c.finish(false)
	}
	return err
}

// ConnSnapshot — учтённые соединения сейчас: открытые и закрытые за
// [connRetain], новые первыми; enabled — учёт включён; skipped — сколько
// не учтено из-за предела открытых.
func ConnSnapshot() (lines []string, enabled bool, skipped uint64) {
	return tracker.snapshot()
}

func (t *connTracker) snapshot() ([]string, bool, uint64) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	keep := t.closed[:0]
	for _, c := range t.closed {
		if now.Sub(c.end) <= connRetain {
			keep = append(keep, c)
		}
	}
	t.closed = keep
	all := make([]*trackedConn, 0, len(t.live)+len(t.closed))
	for _, c := range t.live {
		all = append(all, c)
	}
	all = append(all, t.closed...)
	sort.Slice(all, func(i, j int) bool { return all[i].id > all[j].id })
	lines := make([]string, 0, len(all))
	for _, c := range all {
		lines = append(lines, c.line(now))
	}
	return lines, t.enabled.Load(), t.skipped
}

// line — строка снимка (под t.mu), поля через табуляцию — договор с
// engine.xray.XrayJni.decodeConnections (Kotlin): номер, сеть, вход, источник,
// назначение, имя, протокол, маршрут, состояние, с начала мс, длится мс,
// простой мс, до первого байта мс (-1 — не было), байты к серверу и от
// него, порции к серверу и от него.
func (c *trackedConn) line(now time.Time) string {
	end := now
	if c.state != connOpen {
		end = c.end
	}
	idle := int64(0)
	if last := c.lastActive.Load(); last != 0 {
		idle = now.Sub(time.Unix(0, last)).Milliseconds()
	} else {
		idle = now.Sub(c.start).Milliseconds()
	}
	first := int64(-1)
	if f := c.firstDown.Load(); f != 0 {
		first = time.Unix(0, f).Sub(c.start).Milliseconds()
	}
	fields := []string{
		strconv.FormatUint(c.id, 10), c.network, clean(c.inbound), c.source, c.target,
		clean(c.domain), clean(c.protocol), clean(c.route), c.state,
		strconv.FormatInt(now.Sub(c.start).Milliseconds(), 10),
		strconv.FormatInt(end.Sub(c.start).Milliseconds(), 10),
		strconv.FormatInt(max(idle, 0), 10), strconv.FormatInt(first, 10),
		strconv.FormatInt(c.up.Load(), 10), strconv.FormatInt(c.down.Load(), 10),
		strconv.FormatInt(c.upChunks.Load(), 10), strconv.FormatInt(c.downChunks.Load(), 10),
	}
	return strings.Join(fields, "\t")
}

// clean — без табуляций и переводов строки: поле не ломает строку снимка.
func clean(s string) string {
	return strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return ' '
		}
		return r
	}, s)
}
