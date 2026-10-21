//go:build android

package bridge

// coreTun: на Android вход TUN Xray fd не закрывает (BACKEND_STRATEGY.md,
// §6) — ядро получает fd VpnService как есть.
func coreTun(fd int) (int, error) { return fd, nil }

func releaseCoreTun(int, int) {}
