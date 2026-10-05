//go:build linux

// Command jni — библиотека libdppassxray (D-25): мост tools/xray/bridge
// для JVM через JNI. Собирается `go build -buildmode=c-shared`
// (tools/xray/native.py): для Android — из NDK, для хоста — с jni.h из JDK,
// и тогда тот же код проверяет XrayJniTest в JVM хоста.
//
// Договор с Kotlin — объект engine.xray.XrayJni:
//   - строки идут байтами UTF-8, а не jstring: JNI отдаёт строки в
//     модифицированном UTF-8, и символы вне BMP в тексте ядра или в
//     конфигурации исказились бы;
//   - ответ — массив байтов: первый байт — статус (0 — успех, 5 — успех
//     неполной проверки, иначе bridge.Kind), остальное — текст ошибки ядра
//     (с возможными секретами; редактирует вызывающий);
//   - защитник — объект com.dpsmpx.dppass.engine.SocketProtector: метод
//     protect(int) зовётся из потоков Go, исключение в нём — отказ;
//   - проба DNS (D-32) отвечает своим форматом: исход (bridge.ProbeOutcome),
//     время до ответа в мс и число пришедших байт — по 4 байта, старшим
//     вперёд, — затем текст ошибки.
package main

/*
#include <jni.h>
#include <stdlib.h>

// AttachCurrentThread у JDK принимает void**, у NDK — JNIEnv**.
#ifdef __ANDROID__
#define DPPASS_ENV(e) (e)
#else
#define DPPASS_ENV(e) ((void **)(e))
#endif

static JavaVM *dppass_vm;
static jmethodID dppass_protect_id;

static jbyteArray dppass_new_bytes(JNIEnv *env, const void *p, jsize n) {
	jbyteArray a = (*env)->NewByteArray(env, n);
	if (a != NULL && n > 0) {
		(*env)->SetByteArrayRegion(env, a, 0, n, (const jbyte *)p);
	}
	return a;
}

static jsize dppass_length(JNIEnv *env, jbyteArray a) {
	return a == NULL ? -1 : (*env)->GetArrayLength(env, a);
}

static void dppass_read_bytes(JNIEnv *env, jbyteArray a, jsize n, void *out) {
	(*env)->GetByteArrayRegion(env, a, 0, n, (jbyte *)out);
}

static jlongArray dppass_new_longs(JNIEnv *env, jlong a, jlong b) {
	jlongArray r = (*env)->NewLongArray(env, 2);
	if (r != NULL) {
		jlong v[2] = {a, b};
		(*env)->SetLongArrayRegion(env, r, 0, 2, v);
	}
	return r;
}

// Глобальная ссылка на защитника; NULL — не вышло (исключение снято).
static jobject dppass_hold_protector(JNIEnv *env, jobject p) {
	if (dppass_vm == NULL && (*env)->GetJavaVM(env, &dppass_vm) != JNI_OK) {
		return NULL;
	}
	if (dppass_protect_id == NULL) {
		jclass cls = (*env)->FindClass(env, "com/dpsmpx/dppass/engine/SocketProtector");
		if (cls == NULL) {
			(*env)->ExceptionClear(env);
			return NULL;
		}
		dppass_protect_id = (*env)->GetMethodID(env, cls, "protect", "(I)Z");
		(*env)->DeleteLocalRef(env, cls);
		if (dppass_protect_id == NULL) {
			(*env)->ExceptionClear(env);
			return NULL;
		}
	}
	return (*env)->NewGlobalRef(env, p);
}

static void dppass_release(JNIEnv *env, jobject ref) {
	(*env)->DeleteGlobalRef(env, ref);
}

// Вызов из потока Go: поток присоединяется к JVM на время вызова.
// Любой сбой — отказ: незащищённый сокет мост делает непригодным.
static int dppass_protect(jobject p, int fd) {
	JNIEnv *env = NULL;
	int attached = 0;
	jint st = (*dppass_vm)->GetEnv(dppass_vm, (void **)&env, JNI_VERSION_1_6);
	if (st == JNI_EDETACHED) {
		if ((*dppass_vm)->AttachCurrentThread(dppass_vm, DPPASS_ENV(&env), NULL) != JNI_OK) {
			return 0;
		}
		attached = 1;
	} else if (st != JNI_OK) {
		return 0;
	}
	jboolean ok = (*env)->CallBooleanMethod(env, p, dppass_protect_id, (jint)fd);
	if ((*env)->ExceptionCheck(env)) {
		(*env)->ExceptionClear(env);
		ok = JNI_FALSE;
	}
	if (attached) {
		(*dppass_vm)->DetachCurrentThread(dppass_vm);
	}
	return ok == JNI_TRUE;
}
*/
import "C"

import (
	"encoding/binary"
	"errors"
	"sync"
	"time"
	"unsafe"

	"github.com/dpsmpx/dppass/tools/xray/bridge"
)

// Статусы ответа: 0 и 5 — успех; остальные — bridge.Kind.
const (
	statusOK      = 0
	statusPartial = 5
)

// Ссылки JNI (jobject и производные) cgo представляет числом (uintptr),
// поэтому «нет ссылки» — 0, а не nil.

// jvmProtector — защитник сеанса: глобальная ссылка на объект Java.
// Ссылку освобождает Stop (или неудачный Start) — после того как мост
// снял защитника (bridge.setGuard ждёт вызовы, которые уже идут).
type jvmProtector struct{ ref C.jobject }

func (p jvmProtector) Protect(fd int) bool { return C.dppass_protect(p.ref, C.int(fd)) != 0 }

var (
	jmu     sync.Mutex
	session C.jobject
)

func main() {}

func bytesOf(env *C.JNIEnv, a C.jbyteArray) []byte {
	n := C.dppass_length(env, a)
	if n <= 0 {
		return nil
	}
	b := make([]byte, int(n))
	C.dppass_read_bytes(env, a, n, unsafe.Pointer(&b[0]))
	return b
}

func newBytes(env *C.JNIEnv, b []byte) C.jbyteArray {
	if len(b) == 0 {
		return C.dppass_new_bytes(env, nil, 0)
	}
	return C.dppass_new_bytes(env, unsafe.Pointer(&b[0]), C.jsize(len(b)))
}

func status(env *C.JNIEnv, code byte, text string) C.jbyteArray {
	return newBytes(env, append([]byte{code}, text...))
}

func statusOf(env *C.JNIEnv, err error) C.jbyteArray {
	if err == nil {
		return status(env, statusOK, "")
	}
	var be *bridge.Error
	if errors.As(err, &be) {
		return status(env, byte(be.Kind), be.Error())
	}
	return status(env, byte(bridge.KindStart), err.Error())
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeVersion
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeVersion(env *C.JNIEnv, _ C.jclass) C.jbyteArray {
	return newBytes(env, []byte(bridge.Version()))
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeSetAssetDir
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeSetAssetDir(env *C.JNIEnv, _ C.jclass, dir C.jbyteArray) C.jbyteArray {
	return statusOf(env, bridge.SetAssetDir(string(bytesOf(env, dir))))
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeValidate
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeValidate(env *C.JNIEnv, _ C.jclass, config C.jbyteArray) C.jbyteArray {
	full, err := bridge.Validate(bytesOf(env, config))
	if err == nil && !full {
		return status(env, statusPartial, "")
	}
	return statusOf(env, err)
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeStart
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeStart(
	env *C.JNIEnv, _ C.jclass, config C.jbyteArray, tunFd C.jint, tunMtu C.jint, protector C.jobject,
) C.jbyteArray {
	jmu.Lock()
	defer jmu.Unlock()
	var p bridge.Protector
	var ref C.jobject
	if protector != 0 {
		ref = C.dppass_hold_protector(env, protector)
		if ref == 0 {
			return status(env, byte(bridge.KindContract), "защитник сокетов не принят JNI (нет SocketProtector.protect)")
		}
		p = jvmProtector{ref: ref}
	}
	tun := bridge.Tun{FD: int(tunFd), MTU: int(tunMtu)}
	if err := bridge.Start(bytesOf(env, config), tun, p); err != nil {
		if ref != 0 {
			C.dppass_release(env, ref)
		}
		return statusOf(env, err)
	}
	session = ref
	return status(env, statusOK, "")
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeStop
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeStop(env *C.JNIEnv, _ C.jclass) C.jbyteArray {
	jmu.Lock()
	defer jmu.Unlock()
	err := bridge.Stop()
	if session != 0 {
		C.dppass_release(env, session)
		session = 0
	}
	return statusOf(env, err)
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeTraffic
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeTraffic(env *C.JNIEnv, _ C.jclass) C.jlongArray {
	up, down, ok := bridge.Traffic()
	if !ok {
		return 0
	}
	return C.dppass_new_longs(env, C.jlong(up), C.jlong(down))
}

//export Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeProbeDns
func Java_com_dpsmpx_dppass_engine_xray_XrayJni_nativeProbeDns(env *C.JNIEnv, _ C.jclass, target C.jbyteArray, timeoutMillis C.jint) C.jbyteArray {
	r := bridge.ProbeDNS(string(bytesOf(env, target)), time.Duration(timeoutMillis)*time.Millisecond)
	out := []byte{byte(r.Outcome)}
	out = binary.BigEndian.AppendUint32(out, uint32(min(r.Elapsed.Milliseconds(), 1<<31-1)))
	out = binary.BigEndian.AppendUint32(out, uint32(min(r.Received, 1<<31-1)))
	if r.Err != nil {
		out = append(out, r.Err.Error()...)
	}
	return newBytes(env, out)
}
