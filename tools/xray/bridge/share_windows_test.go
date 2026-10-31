//go:build windows

package bridge

import (
	"errors"
	"net/netip"
	"slices"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Раздача с ПК на Windows (D-101). Объектов ICS в Wine 9.0 нет, поэтому
// перечисление проверяется на поддельных объектах COM: таблицы методов —
// обратные вызовы Go (windows.NewCallback), вызываются тем же путём, что и
// настоящие. Счётчики ссылок после перечисления — те же, что до него.

// fakeCOM — поддельный объект COM; первое поле — comObject, так что
// указатель на fakeCOM — указатель на объект COM.
type fakeCOM struct {
	comObject
	refs int32
	iids []windows.GUID
	// Менеджер.
	coll *fakeCOM
	// Коллекция.
	enum *fakeCOM
	// Перечислитель.
	items  []*fakeCOM
	next   int
	nextHR uint32
	// Подключение и его настройка ICS.
	props   netconProperties
	config  *fakeCOM
	enabled int16
	kind    int32
}

const (
	eNoInterface = 0x80004002
	eFail        = 0x80004005
	eInvalidArg  = 0x80070057
)

var fakeVtables = func() (t struct{ manager, coll, enum, conn, config [16]uintptr }) {
	qi := windows.NewCallback(func(this *fakeCOM, iid *windows.GUID, out **fakeCOM) uintptr {
		if slices.Contains(this.iids, *iid) {
			this.refs++
			*out = this
			return sOK
		}
		*out = nil
		return eNoInterface
	})
	addRef := windows.NewCallback(func(this *fakeCOM) uintptr { this.refs++; return uintptr(this.refs) })
	release := windows.NewCallback(func(this *fakeCOM) uintptr { this.refs--; return uintptr(this.refs) })
	for _, v := range []*[16]uintptr{&t.manager, &t.coll, &t.enum, &t.conn, &t.config} {
		v[0], v[1], v[2] = qi, addRef, release
	}
	t.manager[methodEnumPrivateConnections] = windows.NewCallback(func(this *fakeCOM, flags uintptr, out **fakeCOM) uintptr {
		if flags != icsscEnabled {
			return eInvalidArg
		}
		this.coll.refs++
		*out = this.coll
		return sOK
	})
	t.manager[methodConfigurationFor] = windows.NewCallback(func(_ *fakeCOM, conn *fakeCOM, out **fakeCOM) uintptr {
		conn.config.refs++
		*out = conn.config
		return sOK
	})
	t.coll[methodNewEnum] = windows.NewCallback(func(this *fakeCOM, out **fakeCOM) uintptr {
		this.enum.refs++
		*out = this.enum
		return sOK
	})
	t.enum[methodNext] = windows.NewCallback(func(this *fakeCOM, celt uintptr, v *variant, fetched *uint32) uintptr {
		if this.nextHR != 0 {
			return uintptr(this.nextHR)
		}
		if celt != 1 || this.next >= len(this.items) {
			*fetched = 0
			return sFalse
		}
		item := this.items[this.next]
		this.next++
		item.refs++
		v.vt = vtDispatch
		v.ptr = &item.comObject
		*fetched = 1
		return sOK
	})
	t.conn[methodGetProperties] = windows.NewCallback(func(this *fakeCOM, out **netconProperties) uintptr {
		*out = &this.props
		return sOK
	})
	t.config[methodSharingEnabled] = windows.NewCallback(func(this *fakeCOM, out *int16) uintptr { *out = this.enabled; return sOK })
	t.config[methodSharingConnectionType] = windows.NewCallback(func(this *fakeCOM, out *int32) uintptr { *out = this.kind; return sOK })
	return t
}()

// fakeICS — менеджер с подключениями conns и перечисление по нему.
type fakeICS struct {
	manager, coll, enum *fakeCOM
	conns               []*fakeCOM
	freed               []unsafe.Pointer
}

func newFakeICS(conns ...*fakeCOM) *fakeICS {
	f := &fakeICS{conns: conns}
	f.enum = &fakeCOM{comObject: comObject{&fakeVtables.enum}, iids: []windows.GUID{iidIEnumVARIANT}, items: conns}
	f.coll = &fakeCOM{comObject: comObject{&fakeVtables.coll}, enum: f.enum}
	f.manager = &fakeCOM{comObject: comObject{&fakeVtables.manager}, coll: f.coll}
	return f
}

func fakeConnection(n byte, enabled bool, kind int32) *fakeCOM {
	c := &fakeCOM{comObject: comObject{&fakeVtables.conn}, iids: []windows.GUID{iidINetConnection}}
	c.props.guid = windows.GUID{Data1: uint32(n), Data4: [8]byte{n}}
	c.props.name = &[]uint16{'n', 0}[0]
	c.props.device = &[]uint16{'d', 0}[0]
	c.config = &fakeCOM{comObject: comObject{&fakeVtables.config}, kind: kind}
	if enabled {
		c.config.enabled = variantTrue
	}
	return c
}

func (f *fakeICS) com() icsCOM {
	return icsCOM{
		manager: func() (*comObject, error) { f.manager.refs++; return &f.manager.comObject, nil },
		free:    func(p unsafe.Pointer) { f.freed = append(f.freed, p) },
		clear:   variantClear,
	}
}

// Ссылки отпущены все: после перечисления ни один объект не удержан.
func (f *fakeICS) balanced(t *testing.T) {
	t.Helper()
	all := []*fakeCOM{f.manager, f.coll, f.enum}
	for _, c := range f.conns {
		all = append(all, c, c.config)
	}
	for i, o := range all {
		if o.refs != 0 {
			t.Errorf("объект %d: ссылок %d после перечисления", i, o.refs)
		}
	}
}

// Раздаётся только частная сторона с включённым общим доступом; память
// свойств подключения отдана COM, ссылки отпущены.
func TestICSPrivateConnectionsTakeOnlyEnabledPrivate(t *testing.T) {
	private := fakeConnection(1, true, icsSharingTypePrivate)
	public := fakeConnection(2, true, 0)
	off := fakeConnection(3, false, icsSharingTypePrivate)
	f := newFakeICS(public, private, off)
	guids, err := f.com().private()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(guids, []windows.GUID{private.props.guid}) {
		t.Fatalf("раздаётся %v, ожидалось только частное включённое %v", guids, private.props.guid)
	}
	want := []unsafe.Pointer{unsafe.Pointer(private.props.name), unsafe.Pointer(private.props.device), unsafe.Pointer(&private.props)}
	if !slices.Equal(f.freed, want) {
		t.Fatalf("освобождено %v, ожидалось имя, устройство и сами свойства %v", f.freed, want)
	}
	f.balanced(t)
}

// Отказ на любом шаге — ошибка, а не «раздачи нет»: окно скажет, что ICS
// не ответила. Ссылки отпущены и при отказе.
func TestICSPrivateConnectionsFailClosed(t *testing.T) {
	f := newFakeICS(fakeConnection(1, true, icsSharingTypePrivate))
	f.enum.nextHR = eFail
	if _, err := f.com().private(); err == nil {
		t.Fatal("отказ перечислителя принят за пустой список")
	}
	f.balanced(t)

	f = newFakeICS()
	f.enum.iids = nil
	if _, err := f.com().private(); err == nil {
		t.Fatal("перечислитель без IEnumVARIANT принят")
	}
	f.balanced(t)

	conn := fakeConnection(1, true, icsSharingTypePrivate)
	conn.iids = nil
	f = newFakeICS(conn)
	if _, err := f.com().private(); err == nil {
		t.Fatal("элемент без INetConnection принят")
	}
	f.balanced(t)

	none := icsCOM{manager: func() (*comObject, error) { return nil, fail(KindConfig, "нет") }, free: func(unsafe.Pointer) {}, clear: variantClear}
	var be *Error
	if _, err := none.private(); !errors.As(err, &be) {
		t.Fatalf("менеджер не создан — ошибка моста, получено %v", err)
	}

	// Сломанный перечислитель, который не кончается, — отказ, а не вечный цикл.
	looping := make([]*fakeCOM, maxConnections+1)
	off := fakeConnection(1, false, icsSharingTypePrivate)
	for i := range looping {
		looping[i] = off
	}
	f = newFakeICS(off)
	f.enum.items = looping
	if _, err := f.com().private(); err == nil {
		t.Fatal("перечисление без конца принято")
	}
	f.balanced(t)
}

// Поток COM — свой: функция выполняется, и ответ доходит.
func TestOnCOMThreadRunsAndReturns(t *testing.T) {
	want := []windows.GUID{{Data1: 7}}
	got, err := onCOMThread(func() ([]windows.GUID, error) { return want, nil })
	if err != nil || !slices.Equal(got, want) {
		t.Fatalf("onCOMThread: %v, %v", got, err)
	}
}

// Настоящая ICS: в Wine 9.0 её объектов нет — ответ «ошибка» или пусто, но
// не падение; на Windows — только адреса IPv4.
func TestSharedInterfacesSystemDoesNotCrash(t *testing.T) {
	prefixes, err := SharedInterfaces("DPpass")
	t.Logf("ICS: %v, %v", prefixes, err)
	for _, p := range prefixes {
		if !p.Addr().Is4() {
			t.Fatalf("раздаётся не IPv4: %v", p)
		}
	}
}

// Адреса раздачи: поднятые интерфейсы ICS, только IPv4 «предпочтительные»;
// не раздаются адаптер DPpass и сеть «вверх по течению».
func TestPickSharedExcludesUpstreamAndTunnel(t *testing.T) {
	hotspot, wired, upstream, tun, down := winipcfg.LUID(1), winipcfg.LUID(2), winipcfg.LUID(3), winipcfg.LUID(4), winipcfg.LUID(5)
	candidates := []sharedIface{
		{luid: hotspot, alias: "Local Area Connection* 10", up: true},
		{luid: wired, alias: "Ethernet 2", up: true},
		{luid: upstream, alias: "Wi-Fi", up: true},
		{luid: tun, alias: "DPpass", up: true},
		{luid: down, alias: "Ethernet 3", up: false},
	}
	p := netip.MustParsePrefix
	addrs := []unicastAddr{
		{luid: wired, prefix: p("192.168.138.1/24"), preferred: true},
		{luid: hotspot, prefix: p("192.168.137.1/24"), preferred: true},
		{luid: hotspot, prefix: p("192.168.137.1/24"), preferred: true},
		{luid: hotspot, prefix: p("fe80::1/64"), preferred: true},
		{luid: hotspot, prefix: p("192.168.139.1/24"), preferred: false},
		{luid: upstream, prefix: p("192.0.2.10/24"), preferred: true},
		{luid: tun, prefix: p("172.19.0.1/30"), preferred: true},
		{luid: down, prefix: p("192.168.140.1/24"), preferred: true},
		{luid: winipcfg.LUID(9), prefix: p("10.0.0.1/24"), preferred: true},
	}
	got := pickShared(candidates, "DPpass", upstream, true, addrs)
	want := []netip.Prefix{p("192.168.137.1/24"), p("192.168.138.1/24")}
	if !slices.Equal(got, want) {
		t.Fatalf("раздаются %v, ожидалось %v", got, want)
	}
	// Без маршрута по умолчанию «вверх по течению» нет — исключать нечего.
	if got := pickShared(candidates[2:3], "DPpass", 0, false, addrs); !slices.Equal(got, []netip.Prefix{p("192.0.2.10/24")}) {
		t.Fatalf("без маршрута по умолчанию: %v", got)
	}
}
