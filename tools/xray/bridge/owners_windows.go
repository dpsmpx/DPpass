//go:build windows

package bridge

import (
	"fmt"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Таблицы сокетов Windows с процессами (D-106): iphlpapi загружается только
// из System32 (NewLazySystemDLL), в таблицу импорта DLL моста не попадает.
var (
	iphlpapi                = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUdpTable = iphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	tcpTableOwnerPidAll = 5 // TCP_TABLE_OWNER_PID_ALL
	udpTableOwnerPid    = 1 // UDP_TABLE_OWNER_PID
)

// extendedTable — таблица целиком: размер растёт, пока система не уложится.
func extendedTable(proc *windows.LazyProc, family, class uint32) ([]byte, error) {
	size := uint32(16 << 10)
	for i := 0; i < 8; i++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, uintptr(family), uintptr(class), 0)
		switch windows.Errno(r) {
		case windows.ERROR_SUCCESS:
			return buf, nil
		case windows.ERROR_INSUFFICIENT_BUFFER:
			// Сокеты появляются и между вызовами: с запасом.
			size += 4 << 10
		default:
			return nil, fmt.Errorf("%s: %w", proc.Name, windows.Errno(r))
		}
	}
	return nil, fmt.Errorf("%s: таблица сокетов растёт быстрее, чем читается", proc.Name)
}

// SocketOwners — сокеты TCP и UDP системы (IPv4 и IPv6) с номером и именем
// процесса. Имя процесса чужого пользователя или системы может быть не
// узнать — тогда пусто.
func SocketOwners() ([]SocketOwner, error) {
	parts := []struct {
		proc   *windows.LazyProc
		family uint32
		class  uint32
		parse  func([]byte) ([]SocketOwner, error)
	}{
		{procGetExtendedTcpTable, windows.AF_INET, tcpTableOwnerPidAll, parseTCP4},
		{procGetExtendedTcpTable, windows.AF_INET6, tcpTableOwnerPidAll, parseTCP6},
		{procGetExtendedUdpTable, windows.AF_INET, udpTableOwnerPid, parseUDP4},
		{procGetExtendedUdpTable, windows.AF_INET6, udpTableOwnerPid, parseUDP6},
	}
	var all []SocketOwner
	for _, p := range parts {
		b, err := extendedTable(p.proc, p.family, p.class)
		if err != nil {
			return nil, err
		}
		owners, err := p.parse(b)
		if err != nil {
			return nil, err
		}
		all = append(all, owners...)
	}
	names := map[uint32]string{}
	for i := range all {
		pid := all[i].PID
		name, ok := names[pid]
		if !ok {
			name = processName(pid)
			names[pid] = name
		}
		all[i].Name = name
	}
	return all, nil
}

// processName — имя файла процесса; нет прав или процесс уже ушёл — пусто.
func processName(pid uint32) string {
	if pid == 0 {
		return ""
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n); err != nil {
		return ""
	}
	return filepath.Base(windows.UTF16ToString(buf[:n]))
}
