//go:build linux || windows

// Package bridge — ядро Xray внутри процесса DPpass (D-25): проверка,
// запуск и остановка единственного экземпляра, защита его сокетов от
// петли через TUN и счётчики трафика.
//
// Здесь только Go: мост проверяется `go test` на хосте, а экспорт JNI
// (пакет jni) — тонкая обёртка над ним. Факты о Xray 26.9.30, на которых
// держится код, — docs/research/BACKEND_STRATEGY.md, §6.
//
// Одно ядро на процесс: хуки сокетов, fd TUN (переменная окружения) и
// системный dialer у Xray глобальны. Поэтому всё состояние моста —
// переменные пакета под одной блокировкой.
//
// Платформенное — в своих файлах (D-97): на Android и Linux TUN открывает
// платформа и отдаёт fd, сокеты ядра выводит из туннеля защитник
// (platform_linux.go, protect.go); на Windows адаптер Wintun создаёт сам
// вход TUN ядра, а сокеты привязывает к физическому интерфейсу
// (platform_windows.go).
package bridge

import (
	"bytes"
	"fmt"
	"os"
	"sync"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/stats"
	"github.com/xtls/xray-core/infra/conf/serial"

	// Обработчики, транспорты и службы — те же, что у `xray`, которым
	// шаг hostcheck «Xray» проверяет эталоны компилятора: конфигурацию
	// принимает та же программа, что её запускает (D-24).
	_ "github.com/xtls/xray-core/main/distro/all"
)

// Kind — вид отказа. Числа — договор с engine.xray.XrayFailure.Kind (Kotlin).
type Kind uint8

const (
	// KindConfig — конфигурация не собрана, не прошла политику моста или не принята ядром.
	KindConfig Kind = 1
	// KindStart — конфигурация принята, но ядро не запустилось (или не остановилось).
	KindStart Kind = 2
	// KindRunning — ядро уже запущено: сначала Stop.
	KindRunning Kind = 3
	// KindContract — нарушен договор вызова: fd, MTU, защитник, каталог геоданных.
	KindContract Kind = 4
)

// Error — отказ моста. Текст ядра может содержать адреса и ключи из
// конфигурации: вызывающий редактирует его, прежде чем показать.
type Error struct {
	Kind Kind
	Err  error
}

func (e *Error) Error() string { return e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func fail(kind Kind, format string, args ...any) *Error {
	return &Error{Kind: kind, Err: fmt.Errorf(format, args...)}
}

// Tun — вход TUN: fd платформы и MTU. FD < 0 — без fd: без TUN, а на
// Windows — и с TUN, адаптер которого создаёт ядро (D-97).
type Tun struct {
	FD  int
	MTU int
}

// NoTun — запуск без TUN (хост: тесты и проверки).
var NoTun = Tun{FD: -1}

var (
	mu       sync.Mutex
	current  *core.Instance
	uplink   stats.Counter
	downlink stats.Counter
	assets   string
)

// Счётчики исходящего proxy: TrafficStats DPpass — трафик через сервер (D-25).
const (
	uplinkCounter   = "outbound>>>proxy>>>traffic>>>uplink"
	downlinkCounter = "outbound>>>proxy>>>traffic>>>downlink"
)

// Version — версия ядра, вкомпилированного в мост (сверяется с XrayBackend.VERSION).
func Version() string { return core.Version() }

// SetAssetDir задаёт каталог геоданных (geoip.dat, geosite.dat). Без
// него Xray искал бы их рядом с исполняемым файлом и в системных
// каталогах — в чужих данных. Обязателен до Validate и Start.
func SetAssetDir(dir string) error {
	if dir == "" {
		return fail(KindContract, "пустой каталог геоданных")
	}
	mu.Lock()
	defer mu.Unlock()
	if current != nil {
		return fail(KindRunning, "каталог геоданных не меняется у запущенного ядра")
	}
	if err := os.Setenv(platform.AssetLocation, dir); err != nil {
		return &Error{Kind: KindContract, Err: err}
	}
	assets = dir
	return nil
}

// Validate проверяет конфигурацию без запуска. full=false — проверка
// неполная: ядро запущено, и второй core.New подменил бы ему системный
// dialer (BACKEND_STRATEGY.md, §6), поэтому проверены только сборка и
// политика моста, а полная проверка будет при запуске.
func Validate(config []byte) (full bool, err error) {
	cfg, _, err := build(config)
	if err != nil {
		return false, err
	}
	mu.Lock()
	defer mu.Unlock()
	if assets == "" {
		return false, fail(KindContract, "каталог геоданных не задан (SetAssetDir)")
	}
	if current != nil {
		return false, nil
	}
	inst, err := core.New(cfg)
	if err != nil {
		return false, &Error{Kind: KindConfig, Err: err}
	}
	if err := inst.Close(); err != nil {
		return false, &Error{Kind: KindStart, Err: err}
	}
	return true, nil
}

// Start запускает ядро. На Android и Linux защитник p получает каждый
// исходящий сокет ядра до соединения; его отказ делает сокет непригодным
// (protect.go). С TUN защитник обязателен; без TUN и без защитника сокеты
// не трогаются. На Windows защитника нет: сокеты привязывает ядро (D-97).
func Start(config []byte, tun Tun, p Protector) error {
	cfg, tunIn, err := build(config)
	if err != nil {
		return err
	}
	if err := checkTun(tunIn, tun, p); err != nil {
		return err
	}
	if err := installHook(); err != nil {
		return &Error{Kind: KindStart, Err: err}
	}

	mu.Lock()
	defer mu.Unlock()
	if assets == "" {
		return fail(KindContract, "каталог геоданных не задан (SetAssetDir)")
	}
	if current != nil {
		return fail(KindRunning, "ядро уже запущено; сначала Stop")
	}
	coreFD, err := attachTun(tun)
	if err != nil {
		return &Error{Kind: KindStart, Err: err}
	}
	// Учёт соединений (D-106): обёртка диспетчера — всегда, учёт — по SetConnTracking.
	inst, err := core.New(withConnTracking(cfg))
	if err != nil {
		detachTun(coreFD, tun)
		return &Error{Kind: KindConfig, Err: err}
	}
	sm, _ := inst.GetFeature(stats.ManagerType()).(stats.Manager)
	var up, down stats.Counter
	if sm != nil {
		up, down = sm.GetCounter(uplinkCounter), sm.GetCounter(downlinkCounter)
	}
	if up == nil || down == nil {
		_ = inst.Close()
		detachTun(coreFD, tun)
		return fail(KindConfig, "нет счётчиков исходящего proxy (stats и policy.system.statsOutbound*): конфигурация собрана не компилятором DPpass")
	}
	// Защитник — до Start: исходящие соединения могут начаться сразу.
	armSockets(p)
	if err := inst.Start(); err != nil {
		_ = inst.Close()
		disarmSockets()
		detachTun(coreFD, tun)
		return &Error{Kind: KindStart, Err: err}
	}
	current, uplink, downlink = inst, up, down
	return nil
}

// Stop останавливает ядро; без запущенного — ничего не делает. fd TUN
// платформы ядро не закрывает: на Android вход TUN его не трогает
// (BACKEND_STRATEGY.md, §6), на Linux ядро закрывает свою копию
// (tunfd_desktop.go). Платформа закрывает свой fd после Stop. На Windows
// с ядром уходит и его адаптер Wintun (D-97).
func Stop() error {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return nil
	}
	err := current.Close()
	current, uplink, downlink = nil, nil, nil
	// Сокеты, которые остановленное ядро ещё успело бы открыть, не уходят никуда.
	disarmSockets()
	unsetErr := clearTunEnv()
	if err != nil {
		return &Error{Kind: KindStart, Err: err}
	}
	if unsetErr != nil {
		return &Error{Kind: KindStart, Err: unsetErr}
	}
	return nil
}

// Running — запущено ли ядро.
func Running() bool {
	mu.Lock()
	defer mu.Unlock()
	return current != nil
}

// Traffic — байты через исходящий proxy с запуска; ok=false — ядро не запущено.
func Traffic() (up, down int64, ok bool) {
	mu.Lock()
	defer mu.Unlock()
	if current == nil {
		return 0, 0, false
	}
	return uplink.Value(), downlink.Value(), true
}

// build разбирает JSON, собирает конфигурацию и применяет политику моста.
func build(config []byte) (*core.Config, *tunInbound, error) {
	if len(config) == 0 {
		return nil, nil, fail(KindConfig, "пустая конфигурация")
	}
	jc, err := serial.DecodeJSONConfig(bytes.NewReader(config))
	if err != nil {
		return nil, nil, &Error{Kind: KindConfig, Err: err}
	}
	cfg, err := jc.Build()
	if err != nil {
		return nil, nil, &Error{Kind: KindConfig, Err: err}
	}
	tunIn, err := checkPolicy(cfg)
	if err != nil {
		return nil, nil, &Error{Kind: KindConfig, Err: err}
	}
	return cfg, tunIn, nil
}
