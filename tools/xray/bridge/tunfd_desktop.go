//go:build linux && !android

package bridge

import "golang.org/x/sys/unix"

// coreTun — fd TUN, который получает ядро. Вход TUN Xray на Linux закрывает
// свой fd при остановке (proxy/tun/tun_linux.go, Close), а оркестратор
// запускает ядро по кандидатам плана на одном TUN (D-15) — поэтому ядру
// отдаётся копия, а TUN остаётся у платформы (D-74).
func coreTun(fd int) (int, error) {
	return unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 3)
}

// releaseCoreTun закрывает копию, если ядро её не взяло: запуск не дошёл
// до входа TUN или вход отверг fd, не закрыв его. Взятую ядро уже закрыло,
// и номер мог достаться другому файлу, — поэтому закрывается только fd того
// же TUN, что и у платформы.
func releaseCoreTun(copyFd, orig int) {
	if copyFd >= 0 && copyFd != orig && sameTun(copyFd, orig) {
		_ = unix.Close(copyFd)
	}
}

func sameTun(a, b int) bool {
	na, okA := tunName(a)
	nb, okB := tunName(b)
	return okA && okB && na == nb
}

func tunName(fd int) (string, bool) {
	ifr, err := unix.NewIfreq("")
	if err != nil {
		return "", false
	}
	if err := unix.IoctlIfreq(fd, unix.TUNGETIFF, ifr); err != nil {
		return "", false
	}
	return ifr.Name(), true
}
