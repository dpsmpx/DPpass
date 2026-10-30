//go:build linux || windows

package bridge

// Protector держит сокет ядра вне TUN (на Android — VpnService.protect,
// на Linux — метка SO_MARK, D-74). Ложь — сокет не защищён. На Windows
// защитника нет: сокеты ядра к физическому интерфейсу привязывает вход
// TUN ядра (D-97).
type Protector interface {
	Protect(fd int) bool
}

type allowAll struct{}

func (allowAll) Protect(int) bool { return true }

// denyAll — защитник без сеанса: ядро остановлено, его сокетам незачем соединяться.
type denyAll struct{}

func (denyAll) Protect(int) bool { return false }
