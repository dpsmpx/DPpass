package bridge

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Владельцы сокетов (D-106): процесс у соединения в анализаторе на ПК с
// Windows. Таблицы сокетов системы с номерами процессов отдают
// GetExtendedTcpTable и GetExtendedUdpTable (owners_windows.go); их разбор —
// здесь, без системы, и его проверяет go test на любом хосте.

// SocketOwner — сокет системы и его процесс.
type SocketOwner struct {
	Network string // "tcp" или "udp"
	Local   netip.AddrPort
	Remote  netip.AddrPort // у UDP нет
	PID     uint32
	Name    string // имя файла процесса; "" — не узнать
}

// Размеры строк таблиц iphlpapi (MIB_*ROW_OWNER_PID): поля — DWORD (4 байта)
// и адреса IPv6 по 16 байт; таблица — число строк (DWORD), затем строки.
const (
	tcp4Row = 24 // состояние, адрес, порт, адрес, порт, процесс
	tcp6Row = 56 // адрес, зона, порт, адрес, зона, порт, состояние, процесс
	udp4Row = 12 // адрес, порт, процесс
	udp6Row = 28 // адрес, зона, порт, процесс
)

// rows — строки таблицы: число из заголовка и проверка, что они поместились.
func rows(b []byte, size int) (int, error) {
	if len(b) < 4 {
		return 0, fmt.Errorf("таблица сокетов короче заголовка: %d байт", len(b))
	}
	n := int(binary.LittleEndian.Uint32(b))
	if n < 0 || n > (len(b)-4)/size {
		return 0, fmt.Errorf("в таблице сокетов %d строк по %d байт, а данных %d байт", n, size, len(b)-4)
	}
	return n, nil
}

// Порт — в младших 16 битах DWORD, в сетевом порядке байтов.
func port(b []byte) uint16 { return binary.BigEndian.Uint16(b[:2]) }

func addr4(b []byte) netip.Addr { return netip.AddrFrom4([4]byte(b[:4])) }

func addr6(b []byte) netip.Addr { return netip.AddrFrom16([16]byte(b[:16])).Unmap() }

func parseTCP4(b []byte) ([]SocketOwner, error) {
	n, err := rows(b, tcp4Row)
	if err != nil {
		return nil, err
	}
	out := make([]SocketOwner, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*tcp4Row:]
		out = append(out, SocketOwner{
			Network: "tcp",
			Local:   netip.AddrPortFrom(addr4(r[4:]), port(r[8:])),
			Remote:  netip.AddrPortFrom(addr4(r[12:]), port(r[16:])),
			PID:     binary.LittleEndian.Uint32(r[20:]),
		})
	}
	return out, nil
}

func parseTCP6(b []byte) ([]SocketOwner, error) {
	n, err := rows(b, tcp6Row)
	if err != nil {
		return nil, err
	}
	out := make([]SocketOwner, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*tcp6Row:]
		out = append(out, SocketOwner{
			Network: "tcp",
			Local:   netip.AddrPortFrom(addr6(r[0:]), port(r[20:])),
			Remote:  netip.AddrPortFrom(addr6(r[24:]), port(r[44:])),
			PID:     binary.LittleEndian.Uint32(r[52:]),
		})
	}
	return out, nil
}

func parseUDP4(b []byte) ([]SocketOwner, error) {
	n, err := rows(b, udp4Row)
	if err != nil {
		return nil, err
	}
	out := make([]SocketOwner, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*udp4Row:]
		out = append(out, SocketOwner{Network: "udp", Local: netip.AddrPortFrom(addr4(r[0:]), port(r[4:])), PID: binary.LittleEndian.Uint32(r[8:])})
	}
	return out, nil
}

func parseUDP6(b []byte) ([]SocketOwner, error) {
	n, err := rows(b, udp6Row)
	if err != nil {
		return nil, err
	}
	out := make([]SocketOwner, 0, n)
	for i := 0; i < n; i++ {
		r := b[4+i*udp6Row:]
		out = append(out, SocketOwner{Network: "udp", Local: netip.AddrPortFrom(addr6(r[0:]), port(r[20:])), PID: binary.LittleEndian.Uint32(r[24:])})
	}
	return out, nil
}
