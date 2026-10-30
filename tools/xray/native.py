#!/usr/bin/env python3
"""Сборка библиотеки ядра `libdppassxray` (D-25) — для хоста, Android и Windows.

Библиотека — мост `tools/xray/bridge` и экспорт JNI `tools/xray/jni`,
собранные `go build -buildmode=c-shared` из того же `tools/xray/go.mod`,
по которому шаг «Xray» проверяет компилятор: ядро в APK и ядро в
проверке — одни модули одной версии (D-24). Модули сверяются с `go.sum`
и sum.golang.org (`goenv.py`, T10); бинарники в репозиторий не кладутся.

    python3 tools/xray/native.py host [--race]
        go vet моста и JNI (сборка для APK и для тестов); go test моста в
        обеих сборках (с тегом dppass_testinbound — сквозные тесты через
        тестовый вход на loopback); библиотека для JVM хоста — с тегом
        dppass_testinbound, заголовки JNI из JDK — в build/xray/host/.
        Её загружает тест JNI на хосте (XrayJniTest).

    python3 tools/xray/native.py desktop --out DIR
        библиотека для оболочки Linux (D-74): linux/amd64 этой машины,
        без тестового входа, без таблиц отладки; кроме XrayJni — функции
        LinuxNative (TUN, метка SO_MARK, резолвер с меткой). Результат —
        DIR/libdppassxray.so.

    python3 tools/xray/native.py windows --out DIR
        библиотека для оболочки Windows (D-97): windows/amd64, mingw-w64
        (`x86_64-w64-mingw32-gcc`), заголовки JNI — из закреплённого JDK
        Temurin (`tools/desktop/windows_deps.py`); без тестового входа, без
        таблиц отладки; кроме XrayJni — функции WindowsNative (DPAPI, права
        администратора). Перед сборкой — go vet моста и JNI и тесты моста
        для Windows: собираются всегда, выполняются в Wine (`wine64`), если
        он есть (с --require-tests без Wine — код 3, пропуск шага). Результат —
        DIR/dppassxray.dll.

    python3 tools/xray/native.py android --out DIR [--abi ABI ...]
        библиотека для APK: NDK версии `android-ndk` из
        gradle/libs.versions.toml, ABI arm64-v8a, armeabi-v7a, x86_64,
        API = minSdk; без тестового входа; сегменты ELF выровнены по
        16 КБ. Результат — DIR/<ABI>/libdppassxray.so (так их ждёт
        `sources.jniLibs` у :app, задача xrayNative<Вариант>).

Каждая собранная библиотека проверяется: машина ELF, выравнивание
сегментов PT_LOAD (для Android ≥ 16 КБ), экспортированы ровно функции
`external` объекта `XrayJni` (Kotlin) и, в сборке для Linux, объекта
`LinuxNative` оболочки `desktop` — договор JNI не разойдётся молча. DLL
для Windows — машина PE AMD64, экспорт XrayJni и WindowsNative, импорт
только из системных библиотек (`WINDOWS_IMPORTS`): без рантайма mingw.

Код возврата: 0 — собрано и проверено; 1 — ошибка сборки или проверки;
3 — нет Go, NDK, mingw-w64 или заголовков JNI (без них библиотеку не собрать, D-25).
"""
import argparse
import os
import re
import shutil
import struct
import subprocess
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import goenv  # noqa: E402

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOL = os.path.join(PROJ, "tools", "xray")
CATALOG = os.path.join(PROJ, "gradle", "libs.versions.toml")
KOTLIN_JNI = os.path.join(PROJ, "engine", "src", "main", "kotlin", "com", "dpsmpx", "dppass", "engine", "xray", "XrayRuntime.kt")
HOST_OUT = os.path.join(PROJ, "build", "xray", "host")
LIBRARY = "libdppassxray.so"
JNI_PREFIX = "Java_com_dpsmpx_dppass_engine_xray_XrayJni_"
# Функции оболочки Linux (D-74): в библиотеке для Linux, не для Android.
KOTLIN_DESKTOP_JNI = os.path.join(PROJ, "desktop", "src", "main", "kotlin", "com", "dpsmpx", "dppass", "desktop", "LinuxNative.kt")
DESKTOP_JNI_PREFIX = "Java_com_dpsmpx_dppass_desktop_LinuxNative_"
DESKTOP_OUT = os.path.join(PROJ, "build", "xray", "desktop")
# Функции оболочки Windows (D-97): только в DLL для Windows.
KOTLIN_WINDOWS_JNI = os.path.join(PROJ, "desktop", "src", "main", "kotlin", "com", "dpsmpx", "dppass", "desktop", "WindowsNative.kt")
WINDOWS_JNI_PREFIX = "Java_com_dpsmpx_dppass_desktop_WindowsNative_"
WINDOWS_OUT = os.path.join(PROJ, "build", "xray", "windows")
WINDOWS_LIBRARY = "dppassxray.dll"
WINDOWS_CC = "x86_64-w64-mingw32-gcc"
# Импорт DLL — только системные библиотеки Windows: рантайм mingw
# (libgcc, libwinpthread) рядом не кладётся, и его там быть не должно.
WINDOWS_IMPORTS = {"kernel32.dll", "msvcrt.dll"}
PE_AMD64 = 0x8664
LDFLAGS_DESKTOP = "-s -w -buildid="
PAGE_16K = 16384

# ABI Android → (GOARCH, доп. окружение Go, префикс clang из NDK, машина ELF, 64-бит)
ABIS = {
    "arm64-v8a": ("arm64", {}, "aarch64-linux-android", 183, True),
    "armeabi-v7a": ("arm", {"GOARM": "7"}, "armv7a-linux-androideabi", 40, False),
    "x86_64": ("amd64", {}, "x86_64-linux-android", 62, True),
}
HOST_MACHINES = {"x86_64": 62, "aarch64": 183}

# Флаги сборки библиотеки: воспроизводимость (-trimpath, без buildid и
# сведений VCS), без таблиц символов отладки, страницы 16 КБ (Android 15+).
# -checklinkname=0: github.com/wlynxg/anet (транзитивно: Xray finalmask →
# pion/stun → pion/transport) в interface_android.go берёт net.zoneCache
# через //go:linkname, а компоновщик Go 1.23+ такие ссылки на внутреннее
# стандартной библиотеки запрещает. Править модуль нельзя (replace запрещён,
# check_dependencies.py), поэтому запрет снят только для сборки под Android;
# сама ссылка проверяется компоновщиком (нет символа — сборка падает).
LDFLAGS_ANDROID = f"-s -w -buildid= -checklinkname=0 -extldflags=-Wl,-z,max-page-size={PAGE_16K}"
BUILD_FLAGS = ["-buildmode=c-shared", "-trimpath", "-buildvcs=false"]


class Missing(Exception):
    """Нет инструмента — библиотеку не собрать (код 3)."""


def fail(msg):
    print(f"✗ {msg}")
    return 1


def catalog_versions():
    with open(CATALOG, "rb") as f:
        return tomllib.load(f).get("versions", {})


def run(cmd, env, what):
    r = subprocess.run(cmd, cwd=TOOL, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        out = r.stdout + r.stderr
        tail = "\n".join(out.strip().splitlines()[-40:])
        hint = ""
        if "failed due to signal" in out or "unable to execute command" in out:
            # clang или lld из NDK упал сам (сигнал, например abort после «Pointer tag … was
            # truncated» на Android): сбой инструмента на этой машине, а не ошибка кода.
            hint = ("\n→ компоновщик NDK завершился по сигналу — сбой инструмента сборки на этой машине, "
                    "а не кода DPpass; повторить сборку")
        raise RuntimeError(f"{what}: код {r.returncode}\n{tail}{hint}")
    return r.stdout


# Локальные пакеты, из которых собирается библиотека: их и только их видит
# задача Gradle xrayNative<Вариант> (app/build.gradle.kts, входы).
LIBRARY_PACKAGES = {"jni", "bridge"}


def check_library_packages(env):
    """Библиотека — только из пакетов LIBRARY_PACKAGES: иначе задача Gradle не увидит правку
    нового пакета и оставит в APK старое ядро."""
    module = run(["go", "list", "-m"], env, "go list -m").strip()
    deps = run(["go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", "./jni"], env, "go list ./jni").split()
    local = {d[len(module) + 1:] for d in deps if d.startswith(module + "/")}
    extra = sorted(local - LIBRARY_PACKAGES)
    if extra:
        raise RuntimeError(f"библиотека зависит от локальных пакетов {', '.join(extra)}: добавить их во входы "
                           f"xrayNative (app/build.gradle.kts) и в LIBRARY_PACKAGES")


def base_env():
    if shutil.which("go") is None:
        raise Missing("нет Go (go в PATH) — библиотеку ядра не собрать")
    try:
        env = goenv.go_env()
    except goenv.UnsafeGoEnv as e:
        raise RuntimeError(str(e))
    env["CGO_ENABLED"] = "1"
    return env


# ---- проверка ELF ----

def elf_info(path):
    """(машина, 64-бит, [p_align PT_LOAD], {определённые глобальные функции .dynsym})."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:4] != b"\x7fELF" or data[5] != 1:
        raise RuntimeError(f"{path}: не ELF little-endian")
    is64 = data[4] == 2
    if is64:
        (_, _, machine, _, _, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, _) = struct.unpack_from("<16sHHIQQQIHHHHHH", data)
    else:
        (_, _, machine, _, _, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, _) = struct.unpack_from("<16sHHIIIIIHHHHHH", data)
    aligns = []
    for i in range(phnum):
        off = phoff + i * phentsize
        if is64:
            p_type, _, _, _, _, _, _, p_align = struct.unpack_from("<IIQQQQQQ", data, off)
        else:
            p_type, _, _, _, _, _, _, p_align = struct.unpack_from("<IIIIIIII", data, off)
        if p_type == 1:  # PT_LOAD
            aligns.append(p_align)
    sections = []
    for i in range(shnum):
        off = shoff + i * shentsize
        if is64:
            _, sh_type, _, _, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from("<IIQQQQIIQQ", data, off)
        else:
            _, sh_type, _, _, sh_offset, sh_size, sh_link, _, _, sh_entsize = struct.unpack_from("<IIIIIIIIII", data, off)
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    exported = set()
    for sh_type, offset, size, link, entsize in sections:
        if sh_type != 11 or not entsize:  # SHT_DYNSYM
            continue
        str_off = sections[link][1]
        for k in range(size // entsize):
            o = offset + k * entsize
            if is64:
                st_name, st_info, _, st_shndx, _, _ = struct.unpack_from("<IBBHQQ", data, o)
            else:
                st_name, _, _, st_info, _, st_shndx = struct.unpack_from("<IIIBBH", data, o)
            if st_shndx == 0 or (st_info >> 4) != 1 or (st_info & 0xF) != 2:  # не определена / не GLOBAL / не FUNC
                continue
            end = data.index(b"\0", str_off + st_name)
            exported.add(data[str_off + st_name:end].decode("ascii", "replace"))
    return machine, is64, aligns, exported


def _externals(path, prefix):
    with open(path, encoding="utf-8") as f:
        text = f.read()
    names = set(re.findall(r"\bexternal\s+fun\s+(\w+)\s*\(", text))
    if not names:
        raise RuntimeError(f"{os.path.relpath(path, PROJ)}: не найдено ни одной external fun")
    return {prefix + n for n in names}


def kotlin_externals(linux=False, windows=False):
    """Имена `external fun` объекта XrayJni и, для Linux, LinuxNative, для Windows — WindowsNative:
    договор с экспортом JNI."""
    names = _externals(KOTLIN_JNI, JNI_PREFIX)
    if linux:
        names |= _externals(KOTLIN_DESKTOP_JNI, DESKTOP_JNI_PREFIX)
    if windows:
        names |= _externals(KOTLIN_WINDOWS_JNI, WINDOWS_JNI_PREFIX)
    return names


def check_library(path, machine, is64, min_align, linux=False):
    """Машина, выравнивание и экспорт JNI библиотеки; [linux] — сборка для Linux (D-74) с функциями
    LinuxNative. По умолчанию — Android: так её зовёт и check_apk.py."""
    got_machine, got64, aligns, exported = elf_info(path)
    rel = os.path.relpath(path, PROJ)
    if got_machine != machine or got64 != is64:
        raise RuntimeError(f"{rel}: машина ELF {got_machine} ({'64' if got64 else '32'} бит), ожидалась {machine}")
    if not aligns or min(aligns) < min_align:
        raise RuntimeError(f"{rel}: выравнивание сегментов PT_LOAD {aligns}, нужно ≥ {min_align}")
    want = kotlin_externals(linux)
    jni = {s for s in exported if s.startswith("Java_")}
    if jni != want:
        missing = ", ".join(sorted(want - jni)) or "—"
        extra = ", ".join(sorted(jni - want)) or "—"
        objects = "XrayJni и LinuxNative" if linux else "XrayJni"
        raise RuntimeError(f"{rel}: экспорт JNI не совпадает с {objects} (Kotlin): нет {missing}; лишние {extra}")
    return os.path.getsize(path), min(aligns), len(jni)


def mib(n):
    return f"{n / (1 << 20):.1f} МиБ"


# ---- хост ----

def jni_headers():
    home = os.environ.get("JAVA_HOME")
    if not home:
        java = shutil.which("java")
        if java:
            home = os.path.dirname(os.path.dirname(os.path.realpath(java)))
    inc = os.path.join(home or "", "include")
    if not home or not os.path.isfile(os.path.join(inc, "jni.h")):
        raise Missing("нет заголовков JNI (JAVA_HOME/include/jni.h) — библиотеку для JVM хоста не собрать")
    return [inc, os.path.join(inc, "linux")]


def host(race):
    env = base_env()
    machine = HOST_MACHINES.get(os.uname().machine)
    if machine is None:
        raise Missing(f"хост {os.uname().machine}: сборка для JVM хоста не поддерживается")
    headers = jni_headers()
    env["CGO_CFLAGS"] = " ".join(f"-I{h}" for h in headers)
    for tags in ([], ["-tags", "dppass_testinbound"]):
        run(["go", "vet", *tags, "./bridge", "./jni"], env, f"go vet {' '.join(tags)}".strip())
    extra = ["-race"] if race else []
    for tags in ([], ["-tags", "dppass_testinbound"]):
        run(["go", "test", "-count=1", *extra, *tags, "./bridge"], env, f"go test {' '.join(extra + tags)} ./bridge".replace("  ", " "))
    os.makedirs(HOST_OUT, exist_ok=True)
    out = os.path.join(HOST_OUT, LIBRARY)
    run(["go", "build", *BUILD_FLAGS, "-tags", "dppass_testinbound", "-o", out, "./jni"], env, "сборка библиотеки для хоста")
    _remove_header(out)
    size, align, n = check_library(out, machine, True, 1, linux=True)
    race_note = " (и с -race)" if race else ""
    print(f"✓ мост Xray: go vet и go test{race_note} в обеих сборках; библиотека хоста "
          f"{os.path.relpath(out, PROJ)} {mib(size)}, экспорт JNI — {n} функций XrayJni и LinuxNative")
    return 0


# ---- оболочка Linux (D-74) ----

def desktop(out_dir):
    """Библиотека для пакета ПК: без тестового входа (T11) и без таблиц отладки."""
    env = base_env()
    machine = HOST_MACHINES.get(os.uname().machine)
    if os.uname().machine != "x86_64":
        raise Missing(f"хост {os.uname().machine}: оболочка Linux собирается для x86_64 (D-74)")
    env["CGO_CFLAGS"] = " ".join(f"-I{h}" for h in jni_headers())
    check_library_packages(env)
    run(["go", "vet", "./bridge", "./jni"], env, "go vet")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, LIBRARY)
    run(["go", "build", *BUILD_FLAGS, f"-ldflags={LDFLAGS_DESKTOP}", "-o", out, "./jni"], env, "сборка библиотеки для ПК")
    _remove_header(out)
    size, align, n = check_library(out, machine, True, 1, linux=True)
    print(f"✓ libdppassxray для ПК (linux/amd64, без тестового входа): {os.path.relpath(out, PROJ)} {mib(size)}, "
          f"экспорт JNI — {n} функций XrayJni и LinuxNative")
    return 0


# ---- оболочка Windows (D-97) ----

def pe_info(path):
    """(машина, {имена экспорта}, {DLL импорта в нижнем регистре}) файла PE."""
    with open(path, "rb") as f:
        data = f.read()
    if data[:2] != b"MZ":
        raise RuntimeError(f"{path}: не PE (нет MZ)")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise RuntimeError(f"{path}: нет подписи PE")
    machine, nsections, _, _, _, opt_size, _ = struct.unpack_from("<HHIIIHH", data, pe + 4)
    opt = pe + 24
    if struct.unpack_from("<H", data, opt)[0] != 0x20B:
        raise RuntimeError(f"{path}: не PE32+")
    ndirs = struct.unpack_from("<I", data, opt + 108)[0]
    dirs = [struct.unpack_from("<II", data, opt + 112 + 8 * i) for i in range(min(ndirs, 16))]
    sections = []
    for i in range(nsections):
        off = opt + opt_size + 40 * i
        vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", data, off + 8)
        sections.append((vaddr, max(vsize, rawsize), rawptr))

    def at(rva):
        for vaddr, size, rawptr in sections:
            if vaddr <= rva < vaddr + size:
                return rawptr + rva - vaddr
        raise RuntimeError(f"{path}: RVA {rva:#x} вне секций")

    def cstr(rva):
        o = at(rva)
        return data[o:data.index(b"\0", o)].decode("ascii", "replace")

    exports = set()
    if dirs and dirs[0][0]:
        e = at(dirs[0][0])
        # IMAGE_EXPORT_DIRECTORY: NumberOfNames — +24, AddressOfNames — +32.
        nnames = struct.unpack_from("<I", data, e + 24)[0]
        names_rva = struct.unpack_from("<I", data, e + 32)[0]
        for k in range(nnames):
            exports.add(cstr(struct.unpack_from("<I", data, at(names_rva) + 4 * k)[0]))
    imports = set()
    if len(dirs) > 1 and dirs[1][0]:
        d = at(dirs[1][0])
        while True:
            name_rva = struct.unpack_from("<I", data, d + 12)[0]
            if name_rva == 0:
                break
            imports.add(cstr(name_rva).lower())
            d += 20
    return machine, exports, imports


def check_dll(path):
    """Машина, экспорт JNI и импорт DLL для Windows."""
    machine, exports, imports = pe_info(path)
    rel = os.path.relpath(path, PROJ)
    if machine != PE_AMD64:
        raise RuntimeError(f"{rel}: машина PE {machine:#x}, ожидалась AMD64")
    want = kotlin_externals(windows=True)
    jni = {s for s in exports if s.startswith("Java_")}
    if jni != want:
        missing = ", ".join(sorted(want - jni)) or "—"
        extra = ", ".join(sorted(jni - want)) or "—"
        raise RuntimeError(f"{rel}: экспорт JNI не совпадает с XrayJni и WindowsNative (Kotlin): нет {missing}; лишние {extra}")
    foreign = sorted(imports - WINDOWS_IMPORTS)
    if foreign:
        raise RuntimeError(f"{rel}: импорт не только из системных библиотек: {', '.join(foreign)} — рядом с DLL их нет")
    return os.path.getsize(path), len(jni), sorted(imports)


def windows(out_dir, require_tests):
    """DLL для комплекта Windows: go vet и тесты моста для Windows, сборка mingw-w64, проверка PE.
    [require_tests] — шаг проверок: без Wine тесты моста не выполнить, и это пропуск (код 3), а не успех."""
    env = base_env()
    if shutil.which(WINDOWS_CC) is None:
        raise Missing(f"нет {WINDOWS_CC} (mingw-w64 из Ubuntu: gcc-mingw-w64-x86-64-posix) — DLL для Windows не собрать")
    sys.path.insert(0, os.path.join(PROJ, "tools", "desktop"))
    import windows_deps  # noqa: E402 — заголовки JNI из закреплённого JDK Temurin

    try:
        headers = windows_deps.jni_include()
    except windows_deps.Missing as e:
        raise Missing(str(e))
    env.update(GOOS="windows", GOARCH="amd64", CC=WINDOWS_CC, CGO_CFLAGS=" ".join(f"-I{h}" for h in headers))
    check_library_packages(env)
    run(["go", "vet", "./bridge", "./jni"], env, "go vet (windows)")
    os.makedirs(WINDOWS_OUT, exist_ok=True)
    test_exe = os.path.join(WINDOWS_OUT, "bridge.test.exe")
    run(["go", "test", "-c", "-o", test_exe, "./bridge"], env, "go test -c ./bridge (windows)")
    wine = shutil.which("wine64") or ("/usr/lib/wine/wine64" if os.path.isfile("/usr/lib/wine/wine64") else None)
    if wine is None and require_tests:
        raise Missing("нет wine64 — тесты моста для Windows не выполнить (собраны: go test -c)")
    if wine:
        wenv = dict(os.environ, WINEPREFIX=os.path.join(WINDOWS_OUT, "wine"), WINEDEBUG="-all")
        r = subprocess.run([wine, test_exe, "-test.count=1"], cwd=TOOL, env=wenv, capture_output=True, text=True, timeout=600)
        if r.returncode != 0 or "PASS" not in r.stdout:
            tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-30:])
            raise RuntimeError(f"тесты моста для Windows в Wine: код {r.returncode}\n{tail}")
        tests_note = "тесты моста для Windows — в Wine"
    else:
        tests_note = "тесты моста для Windows собраны, но не запущены: нет wine64"
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, WINDOWS_LIBRARY)
    run(["go", "build", *BUILD_FLAGS, f"-ldflags={LDFLAGS_DESKTOP}", "-o", out, "./jni"], env, "сборка DLL для Windows")
    header = out[:-4] + ".h"
    if os.path.isfile(header):
        os.remove(header)
    size, n, imports = check_dll(out)
    print(f"✓ dppassxray для Windows (windows/amd64, mingw-w64): {os.path.relpath(out, PROJ)} {mib(size)}, "
          f"экспорт JNI — {n} функций XrayJni и WindowsNative, импорт — {', '.join(imports)}; go vet; {tests_note}")
    return 0


# ---- Android ----

def ndk_dir(versions):
    want = versions.get("android-ndk")
    if not want:
        raise RuntimeError("gradle/libs.versions.toml: нет версии android-ndk")
    sdk = os.environ.get("ANDROID_HOME") or os.environ.get("ANDROID_SDK_ROOT")
    if not sdk:
        local = os.path.join(PROJ, "local.properties")
        if os.path.isfile(local):
            for line in open(local, encoding="utf-8"):
                if line.startswith("sdk.dir="):
                    sdk = line.split("=", 1)[1].strip()
    ndk = os.path.join(sdk or "", "ndk", want)
    props = os.path.join(ndk, "source.properties")
    if not sdk or not os.path.isfile(props):
        raise Missing(f"нет NDK {want} (ANDROID_HOME/ndk/{want}): sdkmanager \"ndk;{want}\"")
    with open(props, encoding="utf-8") as f:
        rev = re.search(r"^Pkg\.Revision\s*=\s*(\S+)", f.read(), re.M)
    if not rev or rev.group(1) != want:
        raise RuntimeError(f"{props}: версия NDK {rev.group(1) if rev else '?'}, а в каталоге {want}")
    return ndk, want


def android(out_dir, abis):
    versions = catalog_versions()
    ndk, ndk_version = ndk_dir(versions)
    api = versions.get("android-minSdk")
    env0 = base_env()
    check_library_packages(env0)
    bin_dir = os.path.join(ndk, "toolchains", "llvm", "prebuilt", "linux-x86_64", "bin")
    built = []
    for abi in abis:
        goarch, extra, triple, machine, is64 = ABIS[abi]
        cc = os.path.join(bin_dir, f"{triple}{api}-clang")
        if not os.path.isfile(cc):
            raise Missing(f"в NDK {ndk_version} нет {os.path.basename(cc)}")
        env = dict(env0, GOOS="android", GOARCH=goarch, CC=cc, **extra)
        target_dir = os.path.join(out_dir, abi)
        os.makedirs(target_dir, exist_ok=True)
        out = os.path.join(target_dir, LIBRARY)
        run(["go", "build", *BUILD_FLAGS, f"-ldflags={LDFLAGS_ANDROID}", "-o", out, "./jni"], env, f"сборка {abi}")
        _remove_header(out)
        size, align, n = check_library(out, machine, is64, PAGE_16K, linux=False)
        built.append(f"{abi} {mib(size)}")
    print(f"✓ libdppassxray (NDK {ndk_version}, API {api}): {', '.join(built)}; "
          f"сегменты ELF выровнены по 16 КБ, экспорт JNI совпадает с XrayJni")
    return 0


def _remove_header(lib):
    # c-shared пишет рядом заголовок C; он не нужен ни APK, ни тесту.
    header = lib[:-3] + ".h"
    if os.path.isfile(header):
        os.remove(header)


def main(argv):
    ap = argparse.ArgumentParser(prog="native.py", description="Сборка libdppassxray (D-25)")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("host", help="go vet, go test и библиотека для JVM хоста")
    h.add_argument("--race", action="store_true", help="go test ещё и с -race")
    d = sub.add_parser("desktop", help="библиотека для оболочки Linux (D-74)")
    d.add_argument("--out", default=DESKTOP_OUT, help="каталог для libdppassxray.so")
    w = sub.add_parser("windows", help="DLL для оболочки Windows (D-97)")
    w.add_argument("--out", default=WINDOWS_OUT, help="каталог для dppassxray.dll")
    w.add_argument("--require-tests", action="store_true", help="без wine64 — код 3: тесты моста для Windows не выполнены")
    a = sub.add_parser("android", help="библиотеки для APK")
    a.add_argument("--out", required=True, help="каталог: <ABI>/libdppassxray.so")
    a.add_argument("--abi", action="append", choices=sorted(ABIS), help="ABI (по умолчанию — все три)")
    args = ap.parse_args(argv)
    try:
        if args.cmd == "host":
            return host(args.race)
        if args.cmd == "desktop":
            return desktop(os.path.abspath(args.out))
        if args.cmd == "windows":
            return windows(os.path.abspath(args.out), args.require_tests)
        return android(os.path.abspath(args.out), args.abi or list(ABIS))
    except Missing as e:
        print(f"✗ {e}")
        return 3
    except RuntimeError as e:
        return fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
