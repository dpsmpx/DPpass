//go:build windows

package bridge

import (
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

// Unprotect — обратное Protect; чужой или испорченный блок — ошибка.
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
		return nil, &Error{Kind: KindStart, Err: err}
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return append([]byte(nil), unsafe.Slice(out.Data, out.Size)...), nil
}

// Elevated — процесс запущен с правами администратора (токен повышен UAC).
func Elevated() bool { return windows.GetCurrentProcessToken().IsElevated() }
