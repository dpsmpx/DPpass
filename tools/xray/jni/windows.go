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
	"net/netip"
	"strconv"
	"strings"
	"time"

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

// Интерфейс проб мимо туннеля (D-99): статус 0, затем номер интерфейса
// маршрута по умолчанию мимо адаптера tunAlias и его серверы DNS — по
// строке; иначе — вид отказа и текст.
//
//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeProbeInterface
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeProbeInterface(env *C.JNIEnv, _ C.jclass, tunAlias C.jbyteArray) C.jbyteArray {
	index, dns, err := bridge.ProbeInterface(string(bytesOf(env, tunAlias)))
	if err != nil {
		return statusOf(env, err)
	}
	lines := []string{strconv.FormatUint(uint64(index), 10)}
	for _, a := range dns {
		lines = append(lines, a.String())
	}
	return status(env, statusOK, strings.Join(lines, "\n"))
}

// Привязка сокета пробы handle к интерфейсу index (D-99): статус 0 или
// вид отказа и текст.
//
//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeBindSocket
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeBindSocket(env *C.JNIEnv, _ C.jclass, handle C.jlong, index C.jint) C.jbyteArray {
	return statusOf(env, bridge.BindToInterface(uintptr(handle), uint32(index)))
}

// Адреса имени host у серверов DNS servers (адреса по строке) сокетами,
// привязанными к index (D-99): статус 0 и адреса по строке или отказ.
//
//export Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeResolveVia
func Java_com_dpsmpx_dppass_desktop_WindowsNative_nativeResolveVia(
	env *C.JNIEnv, _ C.jclass, host C.jbyteArray, servers C.jbyteArray, index C.jint, timeoutMillis C.jint,
) C.jbyteArray {
	var list []netip.Addr
	for _, s := range strings.Fields(string(bytesOf(env, servers))) {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return status(env, byte(bridge.KindContract), "сервер DNS не адрес: "+s)
		}
		list = append(list, a)
	}
	addrs, err := bridge.ResolveVia(string(bytesOf(env, host)), list, uint32(index), time.Duration(timeoutMillis)*time.Millisecond)
	if err != nil {
		return statusOf(env, err)
	}
	return status(env, statusOK, strings.Join(addrs, "\n"))
}

func sealed(env *C.JNIEnv, f func([]byte) ([]byte, error), in C.jbyteArray) C.jbyteArray {
	out, err := f(bytesOf(env, in))
	if err != nil {
		return statusOf(env, err)
	}
	return newBytes(env, append([]byte{statusOK}, out...))
}
