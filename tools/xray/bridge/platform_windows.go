//go:build windows

package bridge

import (
	"fmt"
	"slices"

	"github.com/xtls/xray-core/proxy/tun"
	"github.com/xtls/xray-core/transport/internet"
)

// Windows (D-97): адаптер Wintun создаёт и настраивает сам вход TUN ядра,
// fd у платформы нет. Сокеты ядра к физическому интерфейсу привязывает
// хук, который вход TUN ставит при каждом запуске с autoOutboundsInterface
// и не снимает (docs/research/WINDOWS_SHELL.md, §2.4). Мост помнит длину
// списка хуков до запуска и возвращает её после остановки, иначе хуки
// копились бы с каждым кандидатом плана и переподключением.

// checkTun — договор вызова Start: fd и защитника на Windows нет.
func checkTun(_ *tunInbound, tun Tun, p Protector) error {
	switch {
	case tun.FD >= 0:
		return fail(KindContract, "передан fd TUN, а на Windows адаптер создаёт ядро")
	case p != nil:
		return fail(KindContract, "передан защитник сокетов, а на Windows сокеты ядра привязывает его вход TUN")
	}
	return nil
}

// installHook: своего хука на Windows нет.
func installHook() error { return nil }

func attachTun(Tun) (int, error) { return -1, nil }

func detachTun(int, Tun) {}

// hooks — длина internet.Controllers до запуска: её возвращает disarmSockets.
// Под mu моста: Start и Stop идут под ней.
var hooks = -1

func armSockets(Protector) {
	internet.ControllersLock.Lock()
	hooks = len(internet.Controllers)
	internet.ControllersLock.Unlock()
}

func disarmSockets() {
	if hooks < 0 {
		return
	}
	internet.ControllersLock.Lock()
	internet.Controllers = trimHooks(internet.Controllers, hooks)
	internet.ControllersLock.Unlock()
	hooks = -1
}

func clearTunEnv() error { return nil }

// tunName — имя адаптера (XrayBackend.TUN_NAME): по нему ядро открывает или
// создаёт адаптер Wintun, а GUID выводит из имени.
const tunName = "dppass0"

// checkTunFields — вход TUN Windows настраивает систему сам (D-97), и мост
// пропускает только то, что пишет компилятор DPpass: своё имя, адреса,
// маршруты и DNS, привязку сокетов ядра (по маршрутам — "auto", или к
// интерфейсу сети устройства раздачи, D-102) и оба фильтра WFP. Без
// маршрутов или без фильтра «dns» трафик и DNS шли бы мимо TUN; без
// привязки или с привязкой к самому адаптеру сокеты ядра ушли бы в свой же
// TUN — петля.
func checkTunFields(tag string, tc *tun.Config) error {
	switch {
	case tc.Name != tunName:
		return fmt.Errorf("мост: вход TUN %q с адаптером %q, а не %q (D-97)", tag, tc.Name, tunName)
	case len(tc.Gateway) == 0 || len(tc.DNS) == 0 || len(tc.AutoSystemRoutingTable) == 0:
		return fmt.Errorf("мост: вход TUN %q без адресов, DNS или маршрутов — трафик шёл бы мимо TUN (D-97)", tag)
	case tc.AutoOutboundsInterface == "" || tc.AutoOutboundsInterface == tunName:
		return fmt.Errorf("мост: вход TUN %q без привязки сокетов ядра к физическому интерфейсу (autoOutboundsInterface %q) — петля через свой TUN (D-97, D-102)", tag, tc.AutoOutboundsInterface)
	case !slices.Contains(tc.AutoSystemWfpBlockLeak, "dns") || !slices.Contains(tc.AutoSystemWfpBlockLeak, "misconfigtun"):
		return fmt.Errorf("мост: вход TUN %q без фильтров WFP dns и misconfigtun — утечка DNS и IPv6 мимо TUN (D-97)", tag)
	case tc.AutoSystemDnsToGateway:
		return fmt.Errorf("мост: вход TUN %q с autoSystemDnsToGateway — это настройка Linux (D-97)", tag)
	}
	return nil
}
