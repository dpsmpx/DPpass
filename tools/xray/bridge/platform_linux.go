//go:build linux

package bridge

import (
	"fmt"
	"os"
	"strconv"

	"github.com/xtls/xray-core/common/platform"
	"github.com/xtls/xray-core/proxy/tun"
)

// Android и Linux: TUN открывает платформа и отдаёт fd (D-25, D-74), сокеты
// ядра выводит из туннеля защитник (protect.go).

// checkTun — договор вызова Start с TUN: fd, MTU и защитник.
func checkTun(tunIn *tunInbound, tun Tun, p Protector) error {
	switch {
	case tunIn != nil && tun.FD < 0:
		return fail(KindContract, "в конфигурации вход TUN, а fd не передан: ядро читало бы fd 0")
	case tunIn == nil && tun.FD >= 0:
		return fail(KindContract, "передан fd TUN, а входа TUN в конфигурации нет")
	case tunIn != nil && int(tunIn.MTU) != tun.MTU:
		return fail(KindContract, "MTU входа TUN в конфигурации %d, а у TUN %d", tunIn.MTU, tun.MTU)
	case tun.FD >= 0 && p == nil:
		return fail(KindContract, "TUN без защитника сокетов: соединения ядра к серверу ушли бы в туннель")
	}
	return nil
}

// attachTun отдаёт fd ядру переменной окружения Xray: на Linux — копию
// (tunfd_desktop.go), на Android — тот же. Без TUN переменная снимается.
func attachTun(tun Tun) (int, error) {
	if tun.FD < 0 {
		return -1, os.Unsetenv(platform.TunFdKey)
	}
	coreFD, err := coreTun(tun.FD)
	if err != nil {
		return -1, err
	}
	if err := os.Setenv(platform.TunFdKey, strconv.Itoa(coreFD)); err != nil {
		releaseCoreTun(coreFD, tun.FD)
		return -1, err
	}
	return coreFD, nil
}

// detachTun закрывает копию fd, если ядро её не взяло (запуск не удался).
func detachTun(coreFD int, tun Tun) { releaseCoreTun(coreFD, tun.FD) }

// armSockets ставит защитника сеанса; без него сокеты не трогаются.
func armSockets(p Protector) {
	if p != nil {
		setGuard(p)
	} else {
		setGuard(allowAll{})
	}
}

// disarmSockets — после остановки сокеты ядра не уходят никуда.
func disarmSockets() { setGuard(denyAll{}) }

func clearTunEnv() error { return os.Unsetenv(platform.TunFdKey) }

// checkTunFields — вход TUN Android и Linux не трогает систему: адреса,
// маршруты и DNS ставит платформа (D-25, D-74). Поля, которыми вход TUN
// Xray сам настраивает систему (Windows, D-97), здесь — отказ: на Linux
// Xray применил бы адреса и маршруты мимо LinuxRoutes, на Android — сверх
// VpnService.
func checkTunFields(tag string, tc *tun.Config) error {
	if len(tc.Gateway) > 0 || len(tc.DNS) > 0 || len(tc.AutoSystemRoutingTable) > 0 || tc.AutoOutboundsInterface != "" ||
		tc.AutoSystemDnsToGateway || len(tc.AutoSystemWfpBlockLeak) > 0 {
		return fmt.Errorf("мост: вход TUN %q настраивает систему (адреса, маршруты, DNS) — так только на Windows (D-97)", tag)
	}
	return nil
}
