//go:build windows

package bridge

import (
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
