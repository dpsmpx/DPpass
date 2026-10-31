//go:build windows

package bridge

import (
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// Раздача с ПК на Windows (D-101, к D-84): входы прокси — только на
// интерфейсах, которые раздаёт сама Windows, — частной стороне общего
// доступа к подключению к интернету (ICS): «Мобильный хот-спот» и ICS у
// адаптера. Что раздаётся, говорит ICS (COM `HNetCfg.HNetShare`,
// INetSharingManager), а не признаки адаптера: адаптер Wi-Fi Direct бывает
// и клиентом чужой группы, второй провод выглядит так же, как раздача, и
// вход прокси встал бы в чужую сеть. Интерфейс маршрута по умолчанию —
// сеть «вверх по течению» — не раздаётся, что бы ни сказала ICS.
//
// COM — вызовами по таблице методов, без cgo: библиотеки ole32 и oleaut32
// загружаются только из System32 (NewLazySystemDLL), в таблицу импорта DLL
// моста они не попадают.

// SharedInterfaces — адреса IPv4 с длиной префикса на поднятых интерфейсах
// частной стороны ICS, кроме адаптера tunAlias и интерфейса маршрута по
// умолчанию мимо него. Ошибка — раздачи нет: лучше не раздавать, чем
// открыть вход не в той сети.
func SharedInterfaces(tunAlias string) ([]netip.Prefix, error) {
	guids, err := onCOMThread(systemICS.private)
	if err != nil || len(guids) == 0 {
		return nil, err
	}
	candidates := make([]sharedIface, 0, len(guids))
	for i := range guids {
		// Адаптер мог уйти после ответа ICS — тогда он не раздаётся.
		luid, err := winipcfg.LUIDFromGUID(&guids[i])
		if err != nil {
			continue
		}
		row, err := luid.Interface()
		if err != nil {
			continue
		}
		candidates = append(candidates, sharedIface{luid: luid, alias: row.Alias(), up: row.OperStatus == winipcfg.IfOperStatusUp})
	}
	upstream, hasUpstream, _, err := DefaultRoute(tunAlias)
	if err != nil {
		return nil, err
	}
	table, err := winipcfg.GetUnicastIPAddressTable(windows.AF_INET)
	if err != nil {
		return nil, err
	}
	addrs := make([]unicastAddr, 0, len(table))
	for i := range table {
		r := &table[i]
		addrs = append(addrs, unicastAddr{
			luid:      r.InterfaceLUID,
			prefix:    netip.PrefixFrom(r.Address.Addr(), int(r.OnLinkPrefixLength)),
			preferred: r.DadState == winipcfg.DadStatePreferred,
		})
	}
	return pickShared(candidates, tunAlias, upstream.LUID, hasUpstream, addrs), nil
}

// sharedIface — интерфейс частной стороны ICS: поднят ли и его псевдоним.
type sharedIface struct {
	luid  winipcfg.LUID
	alias string
	up    bool
}

// unicastAddr — адрес интерфейса; preferred — проверка дублей пройдена
// (адрес «предпочтительный»), иначе им ещё или уже нельзя пользоваться.
type unicastAddr struct {
	luid      winipcfg.LUID
	prefix    netip.Prefix
	preferred bool
}

// pickShared — адреса IPv4 поднятых интерфейсов из candidates, кроме
// tunAlias и upstream (если hasUpstream). Порядок — по адресу, без
// повторов: одинаковый набор — одинаковый ответ.
func pickShared(candidates []sharedIface, tunAlias string, upstream winipcfg.LUID, hasUpstream bool, addrs []unicastAddr) []netip.Prefix {
	shared := map[winipcfg.LUID]bool{}
	for _, c := range candidates {
		if c.up && c.alias != tunAlias && (!hasUpstream || c.luid != upstream) {
			shared[c.luid] = true
		}
	}
	var out []netip.Prefix
	for _, a := range addrs {
		if shared[a.luid] && a.preferred && a.prefix.IsValid() && a.prefix.Addr().Is4() {
			out = append(out, a.prefix)
		}
	}
	slices.SortFunc(out, func(x, y netip.Prefix) int {
		if c := x.Addr().Compare(y.Addr()); c != 0 {
			return c
		}
		return x.Bits() - y.Bits()
	})
	return slices.Compact(out)
}

// onCOMThread — f на своём потоке с COM (многопоточная модель). Горутина
// завершается, не отпустив поток: Go закрывает такой поток, и состояние COM
// не достаётся другим горутинам моста.
func onCOMThread(f func() ([]windows.GUID, error)) ([]windows.GUID, error) {
	type result struct {
		guids []windows.GUID
		err   error
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread()
		switch err := windows.CoInitializeEx(0, windows.COINIT_MULTITHREADED); err {
		case nil, syscall.Errno(sFalse):
			defer windows.CoUninitialize()
		default:
			done <- result{nil, fail(KindConfig, "COM не запустился: %v", err)}
			return
		}
		g, err := f()
		done <- result{g, err}
	}()
	r := <-done
	return r.guids, r.err
}

// Числа COM: HRESULT, флаги, виды VARIANT, номера методов в таблицах
// (порядок — netcon.h и oaidl.h Windows SDK).
const (
	sOK    = 0
	sFalse = 1

	clsctxInprocServer = 0x1
	clsctxLocalServer  = 0x4

	icsscEnabled          = 1 // ICSSC_ENABLED: только подключения с включённым общим доступом
	icsSharingTypePrivate = 1 // ICSSHARINGTYPE_PRIVATE
	variantTrue           = -1

	vtUnknown  = 13
	vtDispatch = 9

	methodQueryInterface = 0
	methodRelease        = 2

	// INetSharingManager (после IDispatch).
	methodEnumPrivateConnections = 9
	methodConfigurationFor       = 10
	// INetSharingPrivateConnectionCollection.
	methodNewEnum = 7
	// IEnumVARIANT.
	methodNext = 3
	// INetConnection.
	methodGetProperties = 7
	// INetSharingConfiguration.
	methodSharingEnabled        = 7
	methodSharingConnectionType = 8

	// Больше подключений ICS не бывает; дальше — сломанный перечислитель.
	maxConnections = 64
)

var (
	clsidNetSharingManager = windows.GUID{Data1: 0x5c63c1ad, Data2: 0x3956, Data3: 0x4ff8, Data4: [8]byte{0x84, 0x86, 0x40, 0x03, 0x47, 0x58, 0x31, 0x5b}}
	iidINetSharingManager  = windows.GUID{Data1: 0xc08956b7, Data2: 0x1cd3, Data3: 0x11d1, Data4: [8]byte{0xb1, 0xc5, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e}}
	iidINetConnection      = windows.GUID{Data1: 0xc08956a1, Data2: 0x1cd3, Data3: 0x11d1, Data4: [8]byte{0xb1, 0xc5, 0x00, 0x80, 0x5f, 0xc1, 0x27, 0x0e}}
	iidIEnumVARIANT        = windows.GUID{Data1: 0x00020404, Data2: 0x0000, Data3: 0x0000, Data4: [8]byte{0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46}}

	procCoCreateInstance = windows.NewLazySystemDLL("ole32.dll").NewProc("CoCreateInstance")
	procVariantClear     = windows.NewLazySystemDLL("oleaut32.dll").NewProc("VariantClear")
)

// comObject — объект COM: первое слово — указатель на таблицу методов.
// Размер массива — только для индексации: читаются лишь номера из констант.
type comObject struct {
	vtbl *[16]uintptr
}

// call — метод номер method с объектом первым аргументом; ответ — HRESULT.
func (o *comObject) call(method int, args ...uintptr) uint32 {
	r, _, _ := syscall.SyscallN(o.vtbl[method], append([]uintptr{uintptr(unsafe.Pointer(o))}, args...)...)
	return uint32(r)
}

func (o *comObject) release() { o.call(methodRelease) }

// query — интерфейс iid объекта; отказ — HRESULT.
func (o *comObject) query(iid *windows.GUID) (*comObject, uint32) {
	var out *comObject
	hr := o.call(methodQueryInterface, uintptr(unsafe.Pointer(iid)), uintptr(unsafe.Pointer(&out)))
	if failed(hr) || out == nil {
		return nil, hr
	}
	return out, sOK
}

func failed(hr uint32) bool { return int32(hr) < 0 }

// variant — VARIANT Windows (24 байта на amd64); нужны вид и указатель на
// интерфейс (VT_UNKNOWN, VT_DISPATCH).
type variant struct {
	vt  uint16
	_   [3]uint16
	ptr *comObject
	_   uintptr
}

// netconProperties — NETCON_PROPERTIES; строки и сама структура — память
// COM (CoTaskMemFree).
type netconProperties struct {
	guid       windows.GUID
	name       *uint16
	device     *uint16
	status     int32
	mediaType  int32
	character  uint32
	thisObject windows.GUID
	uiObject   windows.GUID
}

// icsCOM — что нужно перечислению: менеджер ICS, освобождение памяти COM
// и VARIANT. В тестах — подмена: объектов ICS в Wine 9.0 нет, перечисление
// проверяется на поддельных объектах COM.
type icsCOM struct {
	manager func() (*comObject, error)
	free    func(unsafe.Pointer)
	clear   func(*variant)
}

var systemICS = icsCOM{manager: sharingManager, free: windows.CoTaskMemFree, clear: variantClear}

func sharingManager() (*comObject, error) {
	if err := procCoCreateInstance.Find(); err != nil {
		return nil, fail(KindConfig, "ole32: %v", err)
	}
	var m *comObject
	r, _, _ := syscall.SyscallN(procCoCreateInstance.Addr(),
		uintptr(unsafe.Pointer(&clsidNetSharingManager)), 0, clsctxInprocServer|clsctxLocalServer,
		uintptr(unsafe.Pointer(&iidINetSharingManager)), uintptr(unsafe.Pointer(&m)))
	if failed(uint32(r)) || m == nil {
		return nil, fail(KindConfig, "менеджер общего доступа (ICS) не создан: HRESULT 0x%08x", uint32(r))
	}
	return m, nil
}

func variantClear(v *variant) {
	if procVariantClear.Find() == nil {
		syscall.SyscallN(procVariantClear.Addr(), uintptr(unsafe.Pointer(v)))
	}
}

// private — GUID подключений частной стороны ICS с включённым общим
// доступом. Каждое подключение ещё сверяется с его настройкой
// (INetSharingConfiguration): включено и частное — иначе не раздаётся.
// Отказ любого шага, кроме одного подключения, — ошибка.
func (c icsCOM) private() ([]windows.GUID, error) {
	m, err := c.manager()
	if err != nil {
		return nil, err
	}
	defer m.release()
	var coll *comObject
	if hr := m.call(methodEnumPrivateConnections, icsscEnabled, uintptr(unsafe.Pointer(&coll))); failed(hr) || coll == nil {
		return nil, hrFail("частные подключения ICS не перечислены", hr)
	}
	defer coll.release()
	var unknown *comObject
	if hr := coll.call(methodNewEnum, uintptr(unsafe.Pointer(&unknown))); failed(hr) || unknown == nil {
		return nil, hrFail("перечислитель подключений ICS не получен", hr)
	}
	enum, hr := unknown.query(&iidIEnumVARIANT)
	unknown.release()
	if enum == nil {
		return nil, hrFail("перечислитель подключений ICS — не IEnumVARIANT", hr)
	}
	defer enum.release()
	var out []windows.GUID
	for i := 0; ; i++ {
		if i == maxConnections {
			return nil, fail(KindConfig, "подключений ICS больше %d — перечислитель сломан", maxConnections)
		}
		var v variant
		var fetched uint32
		hr := enum.call(methodNext, 1, uintptr(unsafe.Pointer(&v)), uintptr(unsafe.Pointer(&fetched)))
		if failed(hr) {
			return nil, hrFail("подключения ICS не прочитаны", hr)
		}
		if hr == sFalse || fetched == 0 {
			return out, nil
		}
		guid, ok, err := c.connection(m, &v)
		c.clear(&v)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, guid)
		}
	}
}

// connection — GUID подключения из элемента перечисления, если общий доступ
// у него включён и подключение — частная сторона; ok=false — не раздаётся.
func (c icsCOM) connection(m *comObject, v *variant) (windows.GUID, bool, error) {
	if (v.vt != vtUnknown && v.vt != vtDispatch) || v.ptr == nil {
		return windows.GUID{}, false, fail(KindConfig, "элемент перечисления ICS вида %d — не подключение", v.vt)
	}
	conn, hr := v.ptr.query(&iidINetConnection)
	if conn == nil {
		return windows.GUID{}, false, hrFail("элемент перечисления ICS — не INetConnection", hr)
	}
	defer conn.release()
	var cfg *comObject
	if hr := m.call(methodConfigurationFor, uintptr(unsafe.Pointer(conn)), uintptr(unsafe.Pointer(&cfg))); failed(hr) || cfg == nil {
		return windows.GUID{}, false, hrFail("настройка ICS подключения не получена", hr)
	}
	defer cfg.release()
	var enabled int16
	var kind int32
	if hr := cfg.call(methodSharingEnabled, uintptr(unsafe.Pointer(&enabled))); failed(hr) {
		return windows.GUID{}, false, hrFail("включён ли общий доступ — не прочитано", hr)
	}
	if hr := cfg.call(methodSharingConnectionType, uintptr(unsafe.Pointer(&kind))); failed(hr) {
		return windows.GUID{}, false, hrFail("сторона общего доступа — не прочитана", hr)
	}
	if enabled != variantTrue || kind != icsSharingTypePrivate {
		return windows.GUID{}, false, nil
	}
	var props *netconProperties
	if hr := conn.call(methodGetProperties, uintptr(unsafe.Pointer(&props))); failed(hr) || props == nil {
		return windows.GUID{}, false, hrFail("свойства подключения ICS не прочитаны", hr)
	}
	guid := props.guid
	c.free(unsafe.Pointer(props.name))
	c.free(unsafe.Pointer(props.device))
	c.free(unsafe.Pointer(props))
	return guid, true, nil
}

func hrFail(what string, hr uint32) *Error {
	return &Error{Kind: KindConfig, Err: fmt.Errorf("%s: HRESULT 0x%08x", what, hr)}
}
