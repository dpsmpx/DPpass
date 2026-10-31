//go:build windows

package main

// Функции оболочки Windows (D-97) — договор с объектом
// desktop.WindowsNative (Kotlin): ответ — статус первым байтом (0 —
// успех, иначе bridge.Kind) и данные или текст ошибки. В библиотеках для
// Android и Linux их нет.

/*
#include <jni.h>
*/
import "C"

import (
	"strings"

	"github.com/dpsmpx/dppass/tools/xray/bridge"
)

//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeProtect
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeProtect(env *C.JNIEnv, _ C.jclass, plain C.jbyteArray) C.jbyteArray {
	return sealed(env, bridge.Protect, plain)
}

//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeUnprotect
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeUnprotect(env *C.JNIEnv, _ C.jclass, data C.jbyteArray) C.jbyteArray {
	return sealed(env, bridge.Unprotect, data)
}

//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeElevated
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeElevated(env *C.JNIEnv, _ C.jclass) C.jboolean {
	if bridge.Elevated() {
		return C.JNI_TRUE
	}
	return C.JNI_FALSE
}

// Тема приложений Windows (D-97): 1 — светлая, 0 — тёмная, -1 — не узнать.
//
//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeSystemTheme
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeSystemTheme(env *C.JNIEnv, _ C.jclass) C.jint {
	light, ok := bridge.AppsUseLightTheme()
	switch {
	case !ok:
		return -1
	case light:
		return 1
	}
	return 0
}

// Маршрут по умолчанию мимо адаптера tunAlias (D-97): статус 0, затем строка
// «поднят ли адаптер (0/1)», и если маршрут есть — псевдоним, шлюз и вид
// через табуляцию; иначе — вид отказа и текст.
//
//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeDefaultRoute
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeDefaultRoute(env *C.JNIEnv, _ C.jclass, tunAlias C.jbyteArray) C.jbyteArray {
	net, ok, up, err := bridge.DefaultRoute(string(bytesOf(env, tunAlias)))
	if err != nil {
		return statusOf(env, err)
	}
	line := "0"
	if up {
		line = "1"
	}
	if ok {
		line += "\n" + strings.Join([]string{net.Alias, net.Gateway, string(rune('0' + net.Kind))}, "\t")
	}
	return status(env, statusOK, line)
}

func sealed(env *C.JNIEnv, f func([]byte) ([]byte, error), in C.jbyteArray) C.jbyteArray {
	out, err := f(bytesOf(env, in))
	if err != nil {
		return statusOf(env, err)
	}
	return newBytes(env, append([]byte{statusOK}, out...))
}
