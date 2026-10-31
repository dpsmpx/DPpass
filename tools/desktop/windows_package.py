#!/usr/bin/env python3
"""Комплект DPpass для Windows x64 (D-97): архив, SHA256SUMS и проверка в Wine.

    python3 tools/desktop/windows_package.py [--out DIR] [--require-tests]

В `build/windows/package/dppass-windows-<версия>/` собирается:

    dppass.exe             запускатель (desktop/windows, mingw-w64): права
                           администратора, проверка прав комплекта (T18)
    runtime/               рантайм jlink из jmods Temurin каталога версий,
                           модули — по jdeps jar; со своим legal/
    runtime/bin/wintun.dll Wintun без изменений и его LICENSE.txt рядом
    lib/                   jar оболочки и модулей (:desktop:installDist)
    native/dppassxray.dll  мост ядра (tools/xray/native.py windows)
    geodata/               набор геоданных
    LICENSE, NOTICES.txt   лицензия DPpass, уведомления о сторонних частях

Состав сверяется: каждого нужного файла — ровно по месту, лишних нет;
dppass.exe — AMD64, окно, манифест `requireAdministrator`, импорт только
системных DLL, без тестовой части; DLL — экспорт JNI = `external` Kotlin;
рантайм — версия Temurin из каталога и модули jdeps, его `.exe` и `.dll`
побайтно как в jmods. Затем, если есть Wine:

  * тестовая сборка запускателя: оценка прав по таблице SDDL, отказ на
    правах файлов Wine (они не настоящие), обход каждого файла комплекта,
    командная строка JVM и окружение без JAVA_TOOL_OPTIONS и подобных;
  * самопроверка оболочки на рантайме комплекта (`--windows-self-check`):
    DLL моста загружена, граф Windows собран без отказов, DPAPI вернул ключ.

Архив — zip без дат и прав (сумма воспроизводится) и SHA256SUMS — в DIR
(по умолчанию `build/windows/dist`).

Код возврата: 0 — готово; 1 — комплект не тот или ошибка; 3 — нет
инструмента (mingw-w64; Wine — с --require-tests) или сети для архивов.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PROJ, "tools", "xray"))
sys.path.insert(0, os.path.join(PROJ, "tools", "desktop"))
sys.path.insert(0, os.path.join(PROJ, "tools", "legal"))
import native  # noqa: E402 — DLL моста и разбор PE
import notices  # noqa: E402 — уведомления из матрицы лицензий
import windows_deps  # noqa: E402 — архивы Temurin и Wintun со сверкой

LAUNCHER = os.path.join(PROJ, "desktop", "windows")
INSTALL = os.path.join(PROJ, "desktop", "build", "install", "dppass-desktop")
OUT = os.path.join(PROJ, "build", "windows")
STAGE = os.path.join(OUT, "package")
DIST = os.path.join(OUT, "dist")
CC = "x86_64-w64-mingw32-gcc"
WINDRES = "x86_64-w64-mingw32-windres"
MINGW_COPYRIGHT = "/usr/share/doc/mingw-w64-common/copyright"
MINGW_VERSION_HEADER = "/usr/share/mingw-w64/include/_mingw_mac.h"
MAIN_CLASS = "com.dpsmpx.dppass.desktop.MainKt"
# Флаги JVM — те же, что пишет запускатель (desktop/windows/dppass.c).
JVM_FLAGS = ["-Dfile.encoding=UTF-8", "-XX:+DisableAttachMechanism", "--enable-native-access=ALL-UNNAMED"]
EXE_IMPORTS = {"kernel32.dll", "user32.dll", "advapi32.dll", "msvcrt.dll"}
PE_SUBSYSTEM_GUI = 2
TOP = {"dppass.exe", "runtime", "lib", "native", "geodata", "LICENSE", "NOTICES.txt"}
REQUIRED = [
    "dppass.exe", "runtime/release", "runtime/bin/javaw.exe", "runtime/bin/java.exe", "runtime/bin/wintun.dll",
    "runtime/bin/LICENSE.txt", "runtime/legal/java.base/LICENSE", "native/dppassxray.dll", "geodata/manifest.json",
    "geodata/NOTICE.txt", "LICENSE", "NOTICES.txt",
]
# Тестовая часть запускателя: её строк в dppass.exe комплекта быть не должно.
TEST_MARKERS = ["--sddl", "--trust-tree", "--walk-tree", "command: "]
# Оценка прав запускателем (T18): строка SDDL → можно ли запускать.
SDDL_CASES = [
    ("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;0x1200a9;;;BU)(A;OICIIO;GA;;;CO)", True, "как у C:\\Program Files"),
    ("O:BAD:P(A;;FA;;;BA)(A;;FA;;;S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464)(A;;0x1200a9;;;WD)", True, "TrustedInstaller"),
    ("O:BAD:P(A;;FA;;;BA)(D;;FA;;;BU)(A;;0x100;;;AU)", True, "запрет и запись атрибутов"),
    ("O:S-1-5-21-1-2-3-1001D:P(A;;FA;;;BA)", False, "владелец — пользователь"),
    ("O:BAD:P(A;;FA;;;BA)(A;;0x1301bf;;;BU)", False, "Users изменяют"),
    ("O:SYD:(A;;GW;;;AU)", False, "Authenticated Users пишут"),
    ("O:BAD:P(A;;FA;;;BA)(A;;0x10000;;;WD)", False, "Everyone удаляет"),
    ("O:BA", False, "нет списка доступа"),
]


class Missing(Exception):
    """Нет инструмента или сети."""


def run(cmd, what, **kw):
    r = subprocess.run(cmd, capture_output=True, text=True, **kw)
    if r.returncode != 0:
        tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-20:])
        raise RuntimeError(f"{what}: код {r.returncode}\n{tail}")
    return r.stdout


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def mib(n):
    return f"{n / (1 << 20):.1f} МиБ"


def version():
    with open(os.path.join(PROJ, "desktop", "build.gradle.kts"), encoding="utf-8") as f:
        m = re.search(r'^version = "([0-9][0-9A-Za-z.]*(?:-[0-9A-Za-z.]+)?)"$', f.read(), re.M)
    if not m:
        raise RuntimeError("desktop/build.gradle.kts: нет строки version = \"…\"")
    return m.group(1)


def numeric(v):
    """0.1.19-dev → 0,1,19,0 — для VERSIONINFO."""
    parts = [int(x) for x in re.match(r"(\d+)\.(\d+)\.(\d+)", v).groups()]
    return ",".join(str(x) for x in parts + [0])


def tool(name):
    path = shutil.which(name)
    if path is None:
        raise Missing(f"нет {name}")
    return path


def wine_binary():
    return shutil.which("wine64") or ("/usr/lib/wine/wine64" if os.path.isfile("/usr/lib/wine/wine64") else None)


def winpath(path):
    """Путь Linux → путь Wine (диск Z: — корень)."""
    return "Z:" + os.path.abspath(path).replace("/", "\\")


def build_launcher(v, out_dir):
    """dppass.exe комплекта и тестовая сборка (для Wine) — из одного исходника."""
    tool(CC)
    tool(WINDRES)
    os.makedirs(out_dir, exist_ok=True)
    res = os.path.join(out_dir, "dppass.res.o")
    # windres зовёт препроцессор через оболочку: кавычки строки — экранированные.
    run([WINDRES, f'-DDPPASS_VERSION=\\"{v}\\"', f"-DDPPASS_VERSION_NUM={numeric(v)}", "-I", LAUNCHER, "-O", "coff",
         "-o", res, os.path.join(LAUNCHER, "dppass.rc")], "windres")
    common = ["-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-municode", "-Wl,--no-insert-timestamp"]
    exe = os.path.join(out_dir, "dppass.exe")
    run([CC, *common, "-mwindows", "-s", "-o", exe, os.path.join(LAUNCHER, "dppass.c"), res, "-ladvapi32"], "сборка dppass.exe")
    test = os.path.join(out_dir, "dppass-test.exe")
    run([CC, *common, "-mconsole", "-DDPPASS_LAUNCHER_TEST", "-o", test, os.path.join(LAUNCHER, "dppass.c"), "-ladvapi32"],
        "тестовая сборка запускателя")
    return exe, test


def subsystem(path):
    with open(path, "rb") as f:
        data = f.read(4096)
    pe = int.from_bytes(data[0x3C:0x40], "little")
    return int.from_bytes(data[pe + 24 + 68:pe + 24 + 70], "little")


def check_launcher(exe):
    machine, _, imports = native.pe_info(exe)
    if machine != native.PE_AMD64:
        raise RuntimeError(f"dppass.exe: машина PE {machine:#x}, ожидалась AMD64")
    if subsystem(exe) != PE_SUBSYSTEM_GUI:
        raise RuntimeError("dppass.exe: не приложение с окном (подсистема PE не GUI)")
    foreign = sorted(imports - EXE_IMPORTS)
    if foreign:
        raise RuntimeError(f"dppass.exe: импорт не только из системных DLL: {', '.join(foreign)}")
    with open(exe, "rb") as f:
        data = f.read()
    if b'requestedExecutionLevel level="requireAdministrator"' not in data:
        raise RuntimeError("dppass.exe: в манифесте нет requireAdministrator — UAC не спросит права (D-97)")
    for marker in TEST_MARKERS:
        if marker.encode("utf-16-le") in data:
            raise RuntimeError(f"dppass.exe: в запускателе комплекта есть тестовая часть ({marker})")
    return sorted(imports)


def jars():
    lib = os.path.join(INSTALL, "lib")
    names = sorted(n for n in os.listdir(lib) if n.endswith(".jar"))
    if not names:
        raise RuntimeError(f"{os.path.relpath(lib, PROJ)}: нет jar")
    return [os.path.join(lib, n) for n in names]


def modules(jar_paths):
    """Модули рантайма — по jdeps jar оболочки и её модулей."""
    cp = os.pathsep.join(jar_paths)
    out = run([tool("jdeps"), "--multi-release", "21", "--ignore-missing-deps", "--print-module-deps", "--class-path", cp, *jar_paths],
              "jdeps")
    mods = out.strip().splitlines()[-1].strip() if out.strip() else ""
    if not re.fullmatch(r"[a-z][a-z0-9.]*(,[a-z][a-z0-9.]*)*", mods) or "java.base" not in mods.split(","):
        raise RuntimeError(f"jdeps: не список модулей: {mods!r}")
    return mods.split(",")


def runtime(target, mods):
    """Рантайм jlink из jmods закреплённого Temurin для Windows."""
    temurin = windows_deps.versions()["temurin"]
    jdk = os.path.join(OUT, f"temurin-{temurin}")
    jmods = os.path.join(jdk, "jmods")
    if not os.path.isfile(os.path.join(jmods, "java.base.jmod")):
        windows_deps.extract("temurin", "jmods/", jdk)
    # Только отладочные атрибуты классов: --strip-debug на Linux прогнал бы и PE Temurin через objcopy —
    # .exe без подписи Eclipse и с датой сборки (сумма комплекта не воспроизводилась бы).
    run([tool("jlink"), "--module-path", jmods, "--add-modules", ",".join(mods), "--strip-java-debug-attributes", "--no-header-files",
         "--no-man-pages", "--compress=zip-6", "--output", target], "jlink")
    release = {}
    with open(os.path.join(target, "release"), encoding="utf-8") as f:
        for line in f:
            k, _, val = line.strip().partition("=")
            release[k] = val.strip('"')
    want = temurin.split("+")[0]
    if release.get("JAVA_VERSION") != want:
        raise RuntimeError(f"рантайм: JAVA_VERSION {release.get('JAVA_VERSION')}, в каталоге — {want}")
    got = set(release.get("MODULES", "").split())
    if not set(mods) <= got:
        raise RuntimeError(f"рантайм: нет модулей {', '.join(sorted(set(mods) - got))}")
    native_files = unchanged_native(target, jmods, got)
    return temurin, sorted(got), native_files


def unchanged_native(target, jmods, mods):
    """Команды и нативные библиотеки (.exe, .dll) рантайма — побайтно те, что в jmods Temurin (на Windows — в bin/)."""
    n = 0
    for m in sorted(mods):
        with zipfile.ZipFile(os.path.join(jmods, f"{m}.jmod")) as z:
            for name in z.namelist():
                section, _, rest = name.partition("/")
                # Исполняемый код Temurin — .exe и .dll (подписаны Eclipse); прочее в lib/ — данные рантайма.
                if section not in ("bin", "lib") or not rest.lower().endswith((".exe", ".dll")):
                    continue
                path = os.path.join(target, "bin", *rest.split("/"))
                if not os.path.isfile(path):
                    raise RuntimeError(f"рантайм: нет bin/{rest} из {m}.jmod")
                with open(path, "rb") as f:
                    if f.read() != z.read(name):
                        raise RuntimeError(f"рантайм: bin/{rest} не совпадает с {m}.jmod — jlink изменил файл Temurin")
                n += 1
    if n == 0:
        raise RuntimeError("рантайм: в jmods нет команд и нативных библиотек — не тот JDK")
    return n


def wintun(bin_dir):
    tmp = tempfile.mkdtemp(prefix="wintun-", dir=OUT)
    try:
        windows_deps.extract("wintun", "bin/amd64/wintun.dll", tmp)
        windows_deps.extract("wintun", "LICENSE.txt", tmp)
        dll = os.path.join(tmp, "bin", "amd64", "wintun.dll")
        machine, exports, _ = native.pe_info(dll)
        if machine != native.PE_AMD64 or "WintunCreateAdapter" not in exports:
            raise RuntimeError("wintun.dll: не AMD64 или нет WintunCreateAdapter")
        shutil.copyfile(dll, os.path.join(bin_dir, "wintun.dll"))
        shutil.copyfile(os.path.join(tmp, "LICENSE.txt"), os.path.join(bin_dir, "LICENSE.txt"))
    finally:
        shutil.rmtree(tmp)
    return windows_deps.versions()["wintun"]


def mingw():
    """(версия CRT mingw-w64, текст ZPL-2.1 из copyright пакета) — CRT статически в dppass.exe и DLL моста."""
    with open(MINGW_VERSION_HEADER, encoding="utf-8") as f:
        h = f.read()
    v = ".".join(re.search(rf"#define __MINGW64_VERSION_{k} (\d+)", h).group(1) for k in ("MAJOR", "MINOR", "BUGFIX"))
    with open(MINGW_COPYRIGHT, encoding="utf-8") as f:
        text = f.read()
    m = re.search(r"^Files: \*\nCopyright: ([^\n]+)\nLicense: ZPL-2.1\n((?: [^\n]*\n)+)", text, re.M)
    if not m:
        raise RuntimeError(f"{MINGW_COPYRIGHT}: нет текста ZPL-2.1 для Files: *")
    body = "\n".join("" if line.strip() == "." else line[1:] for line in m.group(2).splitlines())
    return v, f"Copyright {m.group(1)}\n\n{body.strip()}\n"


def gcc_version():
    return run([CC, "-dumpfullversion"], "gcc").strip()


def write_notices(path, jar_names, temurin, wintun_version, crt_version, zpl):
    tmp = tempfile.mkdtemp(prefix="notices-", dir=OUT)
    try:
        try:
            # Свой jar оболочки — с версией в имени, но не сторонний: строки матрицы ему не нужно.
            notices.build(tmp, [j for j in jar_names if not j.startswith("desktop-")])
        except notices.Missing:
            raise Missing("нет Go — тексты лицензий модулей ядра для NOTICES.txt не получить")
        with open(os.path.join(tmp, notices.SET_DIR, notices.FILE), encoding="utf-8") as f:
            base = f.read().rstrip("\n")
    finally:
        shutil.rmtree(tmp)
    windows = [
        "",
        "== Комплект Windows (D-97) ==",
        "",
        f"* Eclipse Temurin {temurin} — рантайм runtime\\ — GPL-2.0 с Classpath Exception; уведомления рантайма и его частей — runtime\\legal\\",
        f"* Wintun {wintun_version} (WireGuard LLC) — runtime\\bin\\wintun.dll без изменений — Prebuilt Binaries License; текст — runtime\\bin\\LICENSE.txt",
        f"* mingw-w64 {crt_version} — среда выполнения C в dppass.exe и native\\dppassxray.dll — ZPL-2.1, части — общественное достояние; текст ниже",
        f"* GCC {gcc_version()} (libgcc) — в dppass.exe и native\\dppassxray.dll — GPL-3.0 с GCC Runtime Library Exception",
        "",
        "--- ZPL-2.1 (mingw-w64) ---",
        zpl,
    ]
    with open(path, "w", encoding="utf-8") as f:
        f.write(base + "\n" + "\n".join(windows))


def check_tree(root, jar_names):
    present = set(os.listdir(root))
    if present != TOP:
        raise RuntimeError(f"комплект: верхний уровень {sorted(present)}, ожидалось {sorted(TOP)}")
    missing = [p for p in REQUIRED if not os.path.isfile(os.path.join(root, p))]
    if missing:
        raise RuntimeError(f"комплект: нет {', '.join(missing)}")
    lib = sorted(os.listdir(os.path.join(root, "lib")))
    if lib != jar_names:
        raise RuntimeError(f"комплект: lib/ — {lib}, а :desktop:installDist дал {jar_names}")
    for dirpath, _, files in os.walk(root):
        for n in files:
            if n.endswith((".so", ".sh")) or os.path.islink(os.path.join(dirpath, n)):
                raise RuntimeError(f"комплект: {os.path.relpath(os.path.join(dirpath, n), root)} — не для Windows")


def wine_checks(root, test_exe, wine):
    """Запускатель (тестовая сборка) и самопроверка оболочки в Wine."""
    env = dict(os.environ, WINEPREFIX=os.path.join(native.WINDOWS_OUT, "wine"), WINEDEBUG="-all")
    for sddl, safe, what in SDDL_CASES:
        r = subprocess.run([wine, test_exe, "--sddl", sddl], env=env, capture_output=True, text=True, timeout=120)
        got = r.stdout.strip()
        if (r.returncode == 0) != safe or (got == "safe") != safe:
            raise RuntimeError(f"запускатель, {what} ({sddl}): {'можно' if safe else 'отказ'} ожидалось, получено код {r.returncode}: {got}")
    probe = os.path.join(root, "dppass-test.exe")
    shutil.copyfile(test_exe, probe)
    try:
        # Права файлов в Wine — из прав Unix, владелец — пользователь: настоящая проверка отказывает.
        r = subprocess.run([wine, probe], env=env, capture_output=True, text=True, timeout=300)
        if r.returncode != 1 or "Владелец — не администраторы" not in r.stdout:
            raise RuntimeError(f"запускатель: на правах Wine ожидался отказ «владелец», получено код {r.returncode}: {r.stdout.strip()[:300]}")
        # Обход дерева: каждый файл и каталог комплекта (и сам корень) — ровно один раз.
        want_walked = 1 + sum(len(dirs) + len(files) for _, dirs, files in os.walk(root))
        r = subprocess.run([wine, probe, "--walk-tree"], env=env, capture_output=True, text=True, timeout=300)
        if r.returncode != 0 or r.stdout.strip() != f"walked: {want_walked}":
            raise RuntimeError(f"запускатель: обход комплекта — {r.stdout.strip()[:300]}, ожидалось walked: {want_walked}")
        dirty = dict(env, JAVA_TOOL_OPTIONS="-javaagent:x.jar", _JAVA_OPTIONS="-Dx=1", JDK_JAVA_OPTIONS="-Dy=1", CLASSPATH="C:\\x")
        r = subprocess.run([wine, probe, "--trust-tree"], env=dirty, capture_output=True, text=True, timeout=120)
        lines = r.stdout.strip().splitlines()
        javaw = winpath(os.path.join(root, "runtime", "bin", "javaw.exe"))
        want = f'command: "{javaw}" {" ".join(JVM_FLAGS)} -cp "{winpath(os.path.join(root, "lib"))}\\*" {MAIN_CLASS}'
        if r.returncode != 0 or want not in lines:
            raise RuntimeError(f"запускатель: командная строка JVM не та:\n{r.stdout.strip()}\nожидалось:\n{want}")
        left = [line for line in lines if line.startswith("left: ")]
        path = next((line for line in lines if line.startswith("path: ")), "")
        if left or not path.startswith("path: " + winpath(os.path.join(root, "runtime", "bin")) + ";"):
            raise RuntimeError(f"запускатель: окружение JVM не очищено: {left} {path}")
    finally:
        os.remove(probe)
    data = tempfile.mkdtemp(prefix="selfcheck-", dir=OUT)
    try:
        report = os.path.join(data, "report.json")
        java = os.path.join(root, "runtime", "bin", "java.exe")
        cmd = [wine, java, "-Djava.awt.headless=true", *JVM_FLAGS, "-cp", winpath(os.path.join(root, "lib")) + "\\*", MAIN_CLASS,
               "--windows-self-check", winpath(os.path.join(data, "data")), winpath(report)]
        r = subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=600)
        if not os.path.isfile(report):
            tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-20:])
            raise RuntimeError(f"самопроверка оболочки: отчёта нет, код {r.returncode}\n{tail}")
        with open(report, encoding="utf-8") as f:
            rep = json.load(f)
        if r.returncode != 0 or rep.get("host") != "windows" or not rep.get("engine") or rep.get("problems") or not rep.get("dpapi"):
            raise RuntimeError(f"самопроверка оболочки: код {r.returncode}, отчёт {json.dumps({k: v for k, v in rep.items() if k != 'log'}, ensure_ascii=False)}")
        return rep["engine"]
    finally:
        shutil.rmtree(data)


def write_zip(root, target):
    """zip без дат и прав: одинаковые файлы — одинаковая сумма."""
    top = os.path.basename(root)
    files = []
    for dirpath, _, names in os.walk(root):
        for n in names:
            full = os.path.join(dirpath, n)
            files.append((os.path.relpath(full, root).replace(os.sep, "/"), full))
    files.sort()
    with zipfile.ZipFile(target, "w") as z:
        for rel, full in files:
            info = zipfile.ZipInfo(f"{top}/{rel}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            with open(full, "rb") as f:
                z.writestr(info, f.read(), compresslevel=9)
    return len(files)


def package(dist, require_tests):
    v = version()
    wine = wine_binary()
    if wine is None and require_tests:
        raise Missing("нет wine64 — запускатель и рантайм комплекта в Wine не проверить")
    run(["./gradlew", "--console=plain", "-q", ":desktop:installDist"], ":desktop:installDist", cwd=PROJ)
    jar_paths = jars()
    if not any(os.path.basename(p) == f"desktop-{v}.jar" for p in jar_paths):
        raise RuntimeError(f"в lib/ нет desktop-{v}.jar — версия в build.gradle.kts и сборка расходятся")
    root = os.path.join(STAGE, f"dppass-windows-{v}")
    if os.path.exists(STAGE):
        shutil.rmtree(STAGE)
    os.makedirs(os.path.join(root, "lib"))
    mods = modules(jar_paths)
    temurin, runtime_mods, native_files = runtime(os.path.join(root, "runtime"), mods)
    wintun_version = wintun(os.path.join(root, "runtime", "bin"))
    for p in jar_paths:
        shutil.copyfile(p, os.path.join(root, "lib", os.path.basename(p)))
    shutil.copytree(os.path.join(INSTALL, "geodata"), os.path.join(root, "geodata"))
    shutil.copyfile(os.path.join(INSTALL, "LICENSE"), os.path.join(root, "LICENSE"))
    os.makedirs(os.path.join(root, "native"))
    try:
        native.windows(os.path.join(root, "native"), require_tests)
    except native.Missing as e:
        raise Missing(str(e))
    dll_size, n_jni, _ = native.check_dll(os.path.join(root, "native", native.WINDOWS_LIBRARY))
    exe, test_exe = build_launcher(v, os.path.join(OUT, "launcher"))
    shutil.copyfile(exe, os.path.join(root, "dppass.exe"))
    imports = check_launcher(os.path.join(root, "dppass.exe"))
    crt_version, zpl = mingw()
    jar_names = sorted(os.path.basename(p) for p in jar_paths)
    write_notices(os.path.join(root, "NOTICES.txt"), jar_names, temurin, wintun_version, crt_version, zpl)
    check_tree(root, jar_names)
    if wine:
        engine = wine_checks(root, test_exe, wine)
        wine_note = f"в Wine: права — {len(SDDL_CASES)} случаев, обход всего комплекта, командная строка и окружение JVM, самопроверка оболочки (ядро {engine}, DPAPI)"
    else:
        wine_note = "Wine нет: запускатель и рантайм в Wine не проверены"
    os.makedirs(dist, exist_ok=True)
    archive = os.path.join(dist, f"dppass-windows-{v}.zip")
    n = write_zip(root, archive)
    digest = sha256(archive)
    with open(os.path.join(dist, "SHA256SUMS"), "w", encoding="utf-8") as f:
        f.write(f"{digest}  {os.path.basename(archive)}\n")
    print(f"✓ комплект Windows: {os.path.relpath(archive, PROJ)} {mib(os.path.getsize(archive))}, файлов {n}; "
          f"рантайм Temurin {temurin} ({', '.join(runtime_mods)}; {native_files} нативных файлов — как в jmods), Wintun {wintun_version}, DLL моста {mib(dll_size)} ({n_jni} JNI), "
          f"dppass.exe — requireAdministrator, импорт {', '.join(imports)}; {wine_note}")
    return 0


def main(argv):
    ap = argparse.ArgumentParser(prog="windows_package.py", description="Комплект DPpass для Windows x64 (D-97)")
    ap.add_argument("--out", default=DIST, help="каталог для архива и SHA256SUMS")
    ap.add_argument("--require-tests", action="store_true", help="без wine64 — код 3: комплект в Wine не проверен")
    a = ap.parse_args(argv)
    try:
        return package(os.path.abspath(a.out), a.require_tests)
    except (Missing, windows_deps.Missing) as e:
        print(f"✗ {e}")
        return 3
    except RuntimeError as e:
        print(f"✗ {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
