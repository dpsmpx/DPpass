//go:build linux && !android

package main

// Функции оболочки Linux (D-74) — договор с объектом
// desktop.LinuxNative (Kotlin): ответ — число, fd или 0 при успехе,
// иначе −errno (отказ договора — −EINVAL). В библиотеке для Android их нет.

/*
#include <jni.h>
*/
import "C"

import (
	"errors"

	"github.com/dpsmpx/dppass/tools/xray/bridge"
	"golang.org/x/sys/unix"
)

func errnoOf(err error) C.jint {
	if err == nil {
		return 0
	}
	var e unix.Errno
	if errors.As(err, &e) {
		return -C.jint(e)
	}
	return -C.jint(unix.EINVAL)
}

//export Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeOpenTun
func Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeOpenTun(env *C.JNIEnv, _ C.jclass, name C.jbyteArray) C.jint {
	fd, err := bridge.OpenTun(string(bytesOf(env, name)))
	if err != nil {
		return errnoOf(err)
	}
	return C.jint(fd)
}

//export Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeCloseFd
func Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeCloseFd(env *C.JNIEnv, _ C.jclass, fd C.jint) C.jint {
	return errnoOf(bridge.CloseFd(int(fd)))
}

//export Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeMarkSocket
func Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeMarkSocket(env *C.JNIEnv, _ C.jclass, fd C.jint, mark C.jint) C.jint {
	return errnoOf(bridge.MarkSocket(int(fd), int(mark)))
}

//export Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeMarkResolver
func Java_com_dpsmpx_dppass_desktop_LinuxNative_nativeMarkResolver(env *C.JNIEnv, _ C.jclass, mark C.jint) C.jint {
	bridge.MarkResolver(int(mark))
	return 0
}
