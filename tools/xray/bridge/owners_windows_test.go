//go:build windows

package bridge

import (
	"net"
	"os"
	"testing"
)

// Таблицы сокетов настоящей системы: свой слушающий сокет — в таблице. Владельца
// сокета Wine 9.0 не знает (номер процесса 0); названный владелец — только этот
// процесс. Номер процесса у чужого сокета — проверка на ПК с Windows (TODO.md).
func TestSocketOwnersSeeOwnListener(t *testing.T) {
	l, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	want := l.Addr().(*net.TCPAddr).AddrPort()
	owners, err := SocketOwners()
	if err != nil {
		t.Fatalf("таблицы сокетов: %v", err)
	}
	for _, o := range owners {
		if o.Network != "tcp" || o.Local != want {
			continue
		}
		if o.PID == 0 {
			t.Logf("владелец сокета не назван (Wine 9.0): %+v", o)
			return
		}
		if o.PID != uint32(os.Getpid()) || o.Name == "" {
			t.Errorf("слушающий сокет теста — процесс %d «%s», а не %d", o.PID, o.Name, os.Getpid())
		}
		return
	}
	t.Fatalf("слушающего сокета %v нет среди %d сокетов системы", want, len(owners))
}

// Имя процесса по номеру — у своего процесса оно есть; у нулевого — нет.
func TestProcessNameOfSelf(t *testing.T) {
	if name := processName(uint32(os.Getpid())); name == "" {
		t.Error("имя своего процесса не узнано")
	}
	if name := processName(0); name != "" {
		t.Errorf("у процесса 0 имя «%s»", name)
	}
}
