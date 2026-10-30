//go:build windows

package bridge

import (
	"bytes"
	"testing"
)

// Договор Start на Windows (D-97): fd и защитника нет — адаптер и
// привязку сокетов делает вход TUN ядра.
func TestWindowsTunContract(t *testing.T) {
	tun := &tunInbound{MTU: 1500}
	if err := checkTun(tun, Tun{FD: -1}, nil); err != nil {
		t.Fatalf("TUN без fd и без защитника — так и задумано: %v", err)
	}
	if err := checkTun(tun, Tun{FD: 3}, nil); err == nil {
		t.Fatal("fd TUN на Windows принят")
	}
	if err := checkTun(nil, Tun{FD: -1}, allowAll{}); err == nil {
		t.Fatal("защитник сокетов на Windows принят")
	}
}

// Ключ под DPAPI читается обратно, а без добавки DPpass — нет.
func TestDpapiRoundTrip(t *testing.T) {
	key := bytes.Repeat([]byte{0x5a}, 32)
	sealed, err := Protect(key)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, key) {
		t.Fatal("блок DPAPI содержит ключ открыто")
	}
	plain, err := Unprotect(sealed)
	if err != nil || !bytes.Equal(plain, key) {
		t.Fatalf("Unprotect: %x, %v", plain, err)
	}
	sealed[len(sealed)-1] ^= 1
	if _, err := Unprotect(sealed); err == nil {
		t.Fatal("испорченный блок расшифрован")
	}
	if _, err := Protect(nil); err == nil {
		t.Fatal("пустые данные приняты")
	}
}
