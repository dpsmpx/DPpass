//go:build linux

package bridge

import (
	"sync"
	"syscall"

	"github.com/xtls/xray-core/transport/internet"
	"golang.org/x/sys/unix"
)

var (
	guardMu sync.RWMutex
	guard   Protector = denyAll{}

	hookOnce sync.Once
	hookErr  error
	// deadFD — сокет AF_UNIX, которым подменяется незащищённый сокет (poison).
	deadFD = -1
)

func setGuard(p Protector) {
	guardMu.Lock()
	guard = p
	guardMu.Unlock()
}

// installHook ставит хук на сокеты системного dialer Xray — один раз на
// процесс: снять хук Xray не позволяет (BACKEND_STRATEGY.md, §6).
func installHook() error {
	hookOnce.Do(func() {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, 0)
		if err != nil {
			hookErr = err
			return
		}
		deadFD = fd
		hookErr = internet.RegisterDialerController(control)
	})
	return hookErr
}

// control вызывается для каждого исходящего сокета ядра до connect и
// bind. Ошибку хука Xray только журналирует и соединяет дальше, поэтому
// отказ защитника не возвращается ошибкой, а делает сокет непригодным.
func control(_, _ string, c syscall.RawConn) error {
	return c.Control(func(fd uintptr) {
		guardMu.RLock()
		ok := guard.Protect(int(fd))
		guardMu.RUnlock()
		if !ok {
			poison(int(fd))
		}
	})
}

// poison ставит на место fd сокет AF_UNIX (dup3): connect и bind с
// адресом IP на нём дают EINVAL, и Go закрывает свой fd как после любой
// ошибки соединения. Исходный сокет dup3 закрывает до того, как с него
// ушёл хоть один пакет: хук вызывается раньше connect и bind. dup3 на
// занятый номер новых дескрипторов не требует, поэтому не упирается в
// их предел; EBUSY (гонка с open в другом потоке) и EINTR — повтор.
func poison(fd int) {
	for i := 0; i < 8; i++ {
		switch err := unix.Dup3(deadFD, fd, unix.O_CLOEXEC); err {
		case nil:
			return
		case unix.EBUSY, unix.EINTR:
			continue
		default:
			// fd недействителен (EBADF) — соединяться не с чем; на всякий случай закрыть путь и так.
			_ = unix.Shutdown(fd, unix.SHUT_RDWR)
			return
		}
	}
	_ = unix.Shutdown(fd, unix.SHUT_RDWR)
}
