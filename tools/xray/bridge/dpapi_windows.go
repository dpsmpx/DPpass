//go:build windows

package bridge

import (
	"errors"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Функции оболочки Windows (D-97): ключ данных хранилища — под DPAPI
// текущего пользователя (на Linux обёртки нет, D-74), и права
// администратора процесса — без них вход TUN ядра адаптер не создаст.

// dpapiEntropy — своя добавка к ключу DPAPI: блок DPAPI другой программы
// того же пользователя без неё не расшифруется, и наш — тоже без неё.
var dpapiEntropy = []byte("dppass.data-key.v1")

// Protect шифрует plain ключом DPAPI текущего пользователя Windows:
// расшифровать может только он на этом ПК. Без окон (UI_FORBIDDEN).
func Protect(plain []byte) ([]byte, error) {
	if len(plain) == 0 {
		return nil, fail(KindContract, "DPAPI: пустые данные")
	}
	return dpapi(plain, true)
}

// Unprotect — обратное Protect. Блок не открыть никогда — испорчен, другого
// пользователя или ПК, ключ пользователя утрачен (unprotectLost) —
// KindConfig: оболочка считает ключ данных потерянным. Прочие отказы
// (служба, профиль) — KindStart: повторить позже, а не сбрасывать данные.
func Unprotect(sealed []byte) ([]byte, error) {
	if len(sealed) == 0 {
		return nil, fail(KindContract, "DPAPI: пустой блок")
	}
	return dpapi(sealed, false)
}

func dpapi(in []byte, protect bool) ([]byte, error) {
	src := windows.DataBlob{Size: uint32(len(in)), Data: &in[0]}
	entropy := windows.DataBlob{Size: uint32(len(dpapiEntropy)), Data: &dpapiEntropy[0]}
	var out windows.DataBlob
	var err error
	if protect {
		err = windows.CryptProtectData(&src, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	} else {
		err = windows.CryptUnprotectData(&src, nil, &entropy, 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	}
	if err != nil {
		kind := KindStart
		if !protect && unprotectLost(err) {
			kind = KindConfig
		}
		return nil, &Error{Kind: kind, Err: err}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// unprotectLost — отказ CryptUnprotectData, который сам не пройдёт:
// данные неверны (испорчены или не той добавки), ключ не того пользователя
// или ПК, ключ пользователя в негодном состоянии (сброс пароля).
func unprotectLost(err error) bool {
	var errno windows.Errno
	if !errors.As(err, &errno) {
		return false
	}
	switch uintptr(errno) {
	case uintptr(windows.ERROR_INVALID_DATA), uintptr(windows.NTE_BAD_DATA), uintptr(windows.NTE_BAD_KEY_STATE):
		return true
	}
	return false
}

// Elevated — процесс запущен с правами администратора (токен повышен UAC).
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
