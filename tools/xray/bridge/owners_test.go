package bridge

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// Разбор таблиц сокетов Windows (D-106) — на синтетических байтах, как их
// кладёт iphlpapi: DWORD — младшим байтом вперёд, адрес и порт — в сетевом порядке.

func dword(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }

func portField(p uint16) []byte { return []byte{byte(p >> 8), byte(p), 0, 0} }

func table(rows ...[]byte) []byte {
	out := dword(uint32(len(rows)))
	for _, r := range rows {
		out = append(out, r...)
	}
	return out
}

func cat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

func TestSocketTablesParse(t *testing.T) {
	a := netip.MustParseAddr("172.19.0.1").As4()
	r := netip.MustParseAddr("198.51.100.7").As4()
	tcp4, err := parseTCP4(table(cat(dword(5), a[:], portField(40000), r[:], portField(443), dword(4242))))
	if err != nil || len(tcp4) != 1 {
		t.Fatalf("tcp4: %v %v", tcp4, err)
	}
	if got := tcp4[0]; got.Local.String() != "172.19.0.1:40000" || got.Remote.String() != "198.51.100.7:443" || got.PID != 4242 || got.Network != "tcp" {
		t.Errorf("tcp4: %+v", got)
	}

	l6 := netip.MustParseAddr("2001:db8::1").As16()
	r6 := netip.MustParseAddr("::ffff:198.51.100.8").As16()
	tcp6, err := parseTCP6(table(cat(l6[:], dword(0), portField(50000), r6[:], dword(0), portField(443), dword(5), dword(77))))
	if err != nil || len(tcp6) != 1 {
		t.Fatalf("tcp6: %v %v", tcp6, err)
	}
	if got := tcp6[0]; got.Local.String() != "[2001:db8::1]:50000" || got.Remote.String() != "198.51.100.8:443" || got.PID != 77 {
		t.Errorf("tcp6 (адрес IPv4 в IPv6 — как IPv4): %+v", got)
	}

	udp4, err := parseUDP4(table(cat(a[:], portField(5353), dword(9))))
	if err != nil || len(udp4) != 1 || udp4[0].Local.String() != "172.19.0.1:5353" || udp4[0].Remote.IsValid() || udp4[0].PID != 9 {
		t.Errorf("udp4: %+v %v", udp4, err)
	}
	udp6, err := parseUDP6(table(cat(l6[:], dword(0), portField(53), dword(10))))
	if err != nil || len(udp6) != 1 || udp6[0].Local.String() != "[2001:db8::1]:53" || udp6[0].PID != 10 {
		t.Errorf("udp6: %+v %v", udp6, err)
	}
}

func TestSocketTablesRefuseShortData(t *testing.T) {
	if _, err := parseTCP4([]byte{1, 0}); err == nil {
		t.Error("таблица короче заголовка принята")
	}
	// Заголовок обещает две строки, данных — на одну.
	if _, err := parseUDP4(append(dword(2), make([]byte, udp4Row)...)); err == nil {
		t.Error("строки за пределами данных приняты")
	}
	if got, err := parseTCP6(dword(0)); err != nil || len(got) != 0 {
		t.Errorf("пустая таблица: %v %v", got, err)
	}
}
