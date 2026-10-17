#!/usr/bin/env python3
"""Собранный APK — такой, как обещают исходники.

`check_manifest.py` проверяет манифест из исходников, но в APK попадает
итоговый манифест, слитый с манифестами зависимостей, и код всех
зависимостей. Эта проверка смотрит на сам APK (инструменты build-tools
Android SDK: aapt2 и dexdump):

  * итоговый манифест: ровно утверждённые разрешения
    (`check_manifest.PERMISSIONS`), без резервных копий и открытого HTTP,
    компоненты — только объявленные в исходном манифесте (зависимость не
    добавит свой provider или receiver), экспортировано только
    утверждённое, у сервиса VPN — BIND_VPN_SERVICE и тип specialUse,
    `android:process` нет ни у чего (один процесс, D-30);
  * код (dex): классы только из утверждённых корней пакетов — свой код
    и компоненты из матрицы лицензий; SDK аналитики, отчётов о падениях
    и прочий чужой код не попадут незамеченными (D-12, D-20); своих
    тестовых фикстур (модель сети, фиктивное ядро) в APK нет. Классы
    `android.*`/`dalvik.*` допустимы только синтетические — это заглушки,
    которые D8 создаёт для классов платформы новее minSdk;
  * нативный код — ровно библиотека ядра `lib/<ABI>/libdppassxray.so`
    трёх ABI (D-25) и ничего больше: каждая хранится несжатой, её данные в
    zip начинаются на границе 16 КБ, сегменты ELF выровнены по 16 КБ,
    машина ELF — та, что у ABI, экспорт JNI — ровно `external` объекта
    `XrayJni` (страницы 16 КБ — Android 15+; иначе загрузка с mmap из APK
    невозможна);
  * набор геоданных (D-27): `assets/geodata/` — ровно файлы своего
    оглавления и само оглавление; `.dat` сжаты; SHA-256 и размер каждого
    файла — как в оглавлении; источники — те, что в каталоге; атрибуция
    DB-IP на месте; оглавление побайтно совпадает с набором шага «Xray:
    геоданные» (`build/xray/geodata-set`), если шаг был, — две независимые
    сборки дали одно и то же (D-27: сборка детерминирована);
  * уведомления о сторонних компонентах (D-43): `assets/notices/NOTICES.txt`
    есть и называет каждый компонент APK из матрицы лицензий
    (`tools/legal/notices.py --list`) с его версией;
  * размер: APK одного ABI (D-28: выпуск — по APK на ABI) оценивается
    как содержимое этого APK без библиотек других ABI (пустоты, которые
    оставляет пошаговая упаковка AGP, не считаются) и не превышает
    `ABI_APK_BUDGET_MIB` (docs/PERFORMANCE_BUDGET.md, §4).

    python3 tools/hostcheck/check_apk.py [APK] [--abi ABI]
        по умолчанию app/build/outputs/apk/debug/app-debug.apk — все три
        ABI; с --abi — APK одного ABI (тестовые сборки D-35,
        tools/release/sign_apks.py): ровно библиотека этого ABI

Код возврата: 0 — чисто; 1 — нарушения; 2 — нет APK или build-tools
(в полном режиме hostcheck это ошибка, а не пропуск — docs/PROCESS.md).
"""
import argparse
import hashlib
import json
import os
import re
import struct
import subprocess
import sys
import tempfile
import tomllib
import zipfile
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_manifest import EXPORTED_OK, PERMISSIONS  # noqa: E402 — один список утверждённого

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "xray"))
import native  # noqa: E402 — разбор ELF и договор JNI — те же, что при сборке библиотеки

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
APK = os.path.join(PROJ, "app", "build", "outputs", "apk", "debug", "app-debug.apk")
SOURCE_MANIFEST = os.path.join(PROJ, "app", "src", "main", "AndroidManifest.xml")
# Пространство имён кода (app/build.gradle.kts `namespace`): по нему AGP
# раскрывает относительные имена компонентов. У личной сборки applicationId
# случаен (D-47), а namespace постоянен — сверяемся по нему.
NAMESPACE = "com.dpsmpx.dppass"
ANDROID_NS = "http://schemas.android.com/apk/res/android"
A = "{" + ANDROID_NS + "}"
SPECIAL_USE = 0x40000000  # ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
CATALOG = os.path.join(PROJ, "gradle", "libs.versions.toml")
GEODATA_ASSETS = "assets/geodata/"
GEODATA_STEP = os.path.join(PROJ, "build", "xray", "geodata-set", "geodata", "manifest.json")

# Корни пакетов, чьи классы могут быть в APK, — с причиной (строка матрицы лицензий).
CODE_ROOTS = {
    "com/dpsmpx/dppass/": "свой код",
    "kotlin/": "kotlin-stdlib (матрица, §1.1)",
    "kotlinx/": "kotlinx-coroutines (матрица, §1.1)",
    "_COROUTINE/": "kotlinx-coroutines: метки кадров стека (матрица, §1.1)",
    "org/jetbrains/annotations/": "org.jetbrains:annotations (матрица, §1.1)",
    "org/intellij/lang/annotations/": "org.jetbrains:annotations (матрица, §1.1)",
    "com/android/tools/r8/": "поддержка desugaring, которую D8 (AGP) добавляет в APK (матрица, §1.3)",
}
# Свой код, которому в APK не место: тестовые фикстуры (модель сети, здоровье по
# ней, фиктивное ядро) — только для тестов и cli (docs/ARCHITECTURE.md, §2).
TEST_ONLY_CODE = {
    "com/dpsmpx/dppass/network/simulation/": "модель сети",
    "com/dpsmpx/dppass/engine/mock/": "фиктивное ядро",
    "com/dpsmpx/dppass/connection/SimulatedHealthChecker": "здоровье по модели сети",
}
# Только синтетические: заглушки D8 для классов платформы, которых нет на minSdk.
SYNTHETIC_ONLY_ROOTS = ("android/", "dalvik/")
# Нативные библиотеки: ровно ядро Xray (D-25) для каждого ABI — {путь в APK: ABI}.
NATIVE_OK = {f"lib/{abi}/{native.LIBRARY}": abi for abi in native.ABIS}
PAGE_16K = native.PAGE_16K
# Предел APK одного ABI (D-28), МиБ: замер 5 октября 2026 с набором
# геоданных (D-27) — 40,8…44,2 МиБ (больше всех x86_64) плюс запас; до
# набора было 40. Новое значение — вместе с замером (docs/PERFORMANCE_BUDGET.md, §4).
ABI_APK_BUDGET_MIB = 46


def sdk_dir():
    for env in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        d = os.environ.get(env)
        if d and os.path.isdir(d):
            return d
    local = os.path.join(PROJ, "local.properties")
    if os.path.isfile(local):
        for line in open(local, encoding="utf-8"):
            if line.startswith("sdk.dir="):
                d = line.split("=", 1)[1].strip()
                if os.path.isdir(d):
                    return d
    return None


def build_tools(sdk):
    """Каталог build-tools самой новой версии, где есть aapt2 и dexdump."""
    root = os.path.join(sdk, "build-tools")
    if not os.path.isdir(root):
        return None
    def version(v):
        return [int(x) if x.isdigit() else -1 for x in re.split(r"[.-]", v)]
    for v in sorted(os.listdir(root), key=version, reverse=True):
        d = os.path.join(root, v)
        if all(os.path.isfile(os.path.join(d, t)) for t in ("aapt2", "dexdump")):
            return d
    return None


def manifest_tree(aapt2, apk):
    """Итоговый манифест APK (`aapt2 dump xmltree`) → ElementTree с атрибутами android:…."""
    out = subprocess.run([aapt2, "dump", "xmltree", "--file", "AndroidManifest.xml", apk],
                         capture_output=True, text=True, check=True).stdout
    root, stack = None, []  # (отступ, элемент)
    for line in out.splitlines():
        m = re.match(r"^(\s*)([NEA]): (.*)$", line)
        if not m:
            continue
        indent, kind, rest = len(m.group(1)), m.group(2), m.group(3)
        if kind == "E":
            tag = rest.split(" ", 1)[0]
            while stack and stack[-1][0] >= indent:
                stack.pop()
            el = ET.Element(tag) if not stack else ET.SubElement(stack[-1][1], tag)
            root = root if root is not None else el
            stack.append((indent, el))
        elif kind == "A" and stack:
            am = re.match(r'^(?:(\S+?):)?([\w-]+)(?:\(0x[0-9a-f]+\))?=(?:"((?:[^"\\]|\\.)*)"|(\S+))', rest)
            if am:
                ns, name = am.group(1), am.group(2)
                value = am.group(3) if am.group(3) is not None else am.group(4)
                key = A + name if ns == ANDROID_NS else name
                stack[-1][1].set(key, value)
    return root


def dex_classes(dexdump, apk):
    """[(дескриптор вида com/x/Y, синтетический ли)] из всех classes*.dex."""
    classes = []
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(apk) as z:
        for name in sorted(n for n in z.namelist() if re.fullmatch(r"classes\d*\.dex", n)):
            path = z.extract(name, tmp)
            out = subprocess.run([dexdump, "-l", "plain", path], capture_output=True, text=True, check=True).stdout
            current = None
            for line in out.splitlines():
                m = re.match(r"^\s*Class descriptor\s*:\s*'L([^;]+);'", line)
                if m:
                    current = m.group(1)
                    continue
                f = re.match(r"^\s*Access flags\s*:\s*0x([0-9a-f]+)", line)
                if f and current is not None:
                    classes.append((current, bool(int(f.group(1), 16) & 0x1000)))
                    current = None
    return classes


def check_natives(apk, problems, only_abi=None):
    """Нативный код APK — ровно NATIVE_OK (или его библиотека [only_abi]), несжатый и выровненный по 16 КБ (D-25)."""
    sizes = []
    expected = {n: a for n, a in NATIVE_OK.items() if only_abi is None or a == only_abi}
    which = f"ABI {only_abi}" if only_abi else "трёх ABI"
    with zipfile.ZipFile(apk) as z, tempfile.TemporaryDirectory() as tmp:
        infos = {i.filename: i for i in z.infolist()}
        found = {n for n in infos if n.startswith("lib/")}
        for n in sorted(found - set(expected)):
            problems.append(f"нативный код {n}: в APK допускается только {native.LIBRARY} {which} (D-25)")
        for n, abi in sorted(expected.items()):
            info = infos.get(n)
            if info is None:
                problems.append(f"нет {n}: APK без ядра для {abi} бесполезен (D-25)")
                continue
            if info.compress_type != zipfile.ZIP_STORED:
                problems.append(f"{n}: сжата — библиотека должна лежать в APK несжатой (загрузка прямо из APK)")
            # Данные записи начинаются после локального заголовка: 30 байт + имя + поле extra.
            with open(apk, "rb") as f:
                f.seek(info.header_offset + 26)
                name_len, extra_len = struct.unpack("<HH", f.read(4))
            data_offset = info.header_offset + 30 + name_len + extra_len
            if data_offset % PAGE_16K:
                problems.append(f"{n}: данные в zip со смещения {data_offset}, не кратного 16 КБ")
            path = z.extract(n, tmp)
            machine, is64 = native.ABIS[abi][3], native.ABIS[abi][4]
            try:
                native.check_library(path, machine, is64, PAGE_16K)
            except RuntimeError as e:
                problems.append(f"{n}: {str(e).split(': ', 1)[-1]}")
            sizes.append(f"{abi} {info.file_size / 1024 / 1024:.1f} МиБ")
    return ", ".join(sizes)


def check_geodata(apk, problems):
    """Набор геоданных в APK (D-27) — строка итога или None при ошибке."""
    with zipfile.ZipFile(apk) as z:
        infos = {i.filename[len(GEODATA_ASSETS):]: i for i in z.infolist() if i.filename.startswith(GEODATA_ASSETS)}
        if "manifest.json" not in infos:
            problems.append(f"нет {GEODATA_ASSETS}manifest.json: набора геоданных в APK нет — правила с geoip/geosite "
                            "на устройстве отвергаются (D-27; задача xrayGeodata<Вариант>)")
            return None
        raw = z.read(GEODATA_ASSETS + "manifest.json")
        try:
            m = json.loads(raw)
            files = {f["name"]: f for f in m["files"]}
            dlc, dbip = m["sources"]["dlc"]["version"], m["sources"]["dbip"]["release"]
        except (ValueError, KeyError, TypeError) as e:
            problems.append(f"{GEODATA_ASSETS}manifest.json не читается: {e}")
            return None
        for name in sorted(set(infos) - set(files) - {"manifest.json"}):
            problems.append(f"{GEODATA_ASSETS}{name}: файла нет в оглавлении набора")
        packed = unpacked = 0
        for name, f in sorted(files.items()):
            info = infos.get(name)
            if info is None:
                problems.append(f"нет {GEODATA_ASSETS}{name} из оглавления набора")
                continue
            data = z.read(info)
            if hashlib.sha256(data).hexdigest() != f["sha256"] or len(data) != f["size"]:
                problems.append(f"{GEODATA_ASSETS}{name}: SHA-256 или размер не совпали с оглавлением")
            if name.endswith(".dat") and info.compress_type != zipfile.ZIP_DEFLATED:
                problems.append(f"{GEODATA_ASSETS}{name}: не сжат — набор лежит в APK сжатым (D-27)")
            if name == "NOTICE.txt" and b"IP Geolocation by DB-IP" not in data:
                problems.append(f"{GEODATA_ASSETS}NOTICE.txt: нет атрибуции «IP Geolocation by DB-IP» (CC BY 4.0, D-27)")
            packed += info.compress_size
            unpacked += info.file_size
    with open(CATALOG, "rb") as fh:
        versions = tomllib.load(fh).get("versions", {})
    if (dlc, dbip) != (versions.get("geodata-dlc"), versions.get("geodata-dbip")):
        problems.append(f"набор в APK собран из dlc {dlc} и DB-IP {dbip}, а в каталоге — "
                        f"{versions.get('geodata-dlc')} и {versions.get('geodata-dbip')}")
    step = "шаг «Xray: геоданные» не запускался — с ним не сверено"
    if os.path.isfile(GEODATA_STEP):
        with open(GEODATA_STEP, "rb") as fh:
            if fh.read() != raw:
                problems.append("оглавление набора в APK не совпало с набором шага «Xray: геоданные» "
                                "из тех же источников — сборка набора не детерминирована (D-27)")
        step = "совпадает с набором шага «Xray: геоданные»"
    return (f"набор геоданных — dlc {m['sources']['dlc']['commit']}, DB-IP {dbip}, "
            f"{unpacked / 1024 / 1024:.1f} → {packed / 1024 / 1024:.1f} МиБ в APK, сверен с оглавлением, {step}")


def entry_span(f, i):
    """Байты записи в файле: локальный заголовок (30 байт, имя, его extra — там
    выравнивание), данные и дескриптор данных (если есть)."""
    f.seek(i.header_offset + 26)
    name_len, extra_len = struct.unpack("<HH", f.read(4))
    return 30 + name_len + extra_len + i.compress_size + (16 if i.flag_bits & 0x08 else 0)


def apk_layout(apk):
    """(байт содержимого, байт пустот, {ABI: байт записей lib/<ABI>/}).

    Содержимое — записи, центральный каталог, конец каталога и блок
    подписи. Пустоты — то, что между записями: пошаговая упаковка AGP
    переписывает APK на месте и оставляет дыры от прежних версий записей.
    В выпускаемый APK они не попадают, поэтому размер оценивается по
    содержимому, а не по размеру файла.
    """
    size = os.path.getsize(apk)
    per_abi = {}
    with zipfile.ZipFile(apk) as z, open(apk, "rb") as f:
        used = 0
        for i in z.infolist():
            span = entry_span(f, i)
            used += span
            parts = i.filename.split("/")
            if len(parts) > 2 and parts[0] == "lib":
                central = 46 + len(i.orig_filename.encode()) + len(i.extra) + len(i.comment)
                per_abi[parts[1]] = per_abi.get(parts[1], 0) + span + central
        f.seek(-22, 2)
        eocd = f.read(22)
        if eocd[:4] != b"PK\x05\x06":
            raise RuntimeError("конец центрального каталога не в последних 22 байтах (комментарий zip?)")
        cd_size, cd_offset = struct.unpack("<II", eocd[12:20])
        f.seek(cd_offset - 24)
        tail = f.read(24)
        signing = struct.unpack("<Q", tail[:8])[0] + 8 if tail[8:] == b"APK Sig Block 42" else 0
    used += cd_size + len(eocd) + signing
    return used, size - used, per_abi


def abi_apk_sizes(apk):
    """{ABI: байт} — сколько весил бы APK только с этим ABI (D-28), и байт пустот файла.

    Из содержимого APK вычитаются записи `lib/<другой ABI>/`: данные,
    локальный заголовок и запись центрального каталога (46 байт, имя,
    extra, комментарий).
    """
    used, holes, per_abi = apk_layout(apk)
    return {abi: used - sum(c for other, c in per_abi.items() if other != abi) for abi in per_abi}, holes


NOTICES_ASSET = "assets/notices/NOTICES.txt"


def check_notices(apk, problems):
    """Уведомления о компонентах (D-43): каждый компонент APK из матрицы — с версией. Строка итога или None."""
    sys.path.insert(0, os.path.join(PROJ, "tools", "legal"))
    import notices  # noqa: E402 — тот же разбор матрицы, что у сборщика уведомлений
    with zipfile.ZipFile(apk) as z:
        if NOTICES_ASSET not in z.namelist():
            problems.append(f"нет {NOTICES_ASSET}: уведомлений о сторонних компонентах в APK нет (D-43; задача legalNotices<Вариант>)")
            return None
        text = z.read(NOTICES_ASSET).decode("utf-8", errors="replace")
    expected = [(name, version) for kind, name, version, _ in notices.components() if kind != "data"]
    missing = [f"{n} {v}" for n, v in expected if f"* {n} {v} —" not in text]
    for m in missing:
        problems.append(f"{NOTICES_ASSET}: нет уведомления о {m} из матрицы лицензий (D-43)")
    if "Go (среда выполнения)" not in text:
        problems.append(f"{NOTICES_ASSET}: нет уведомления о среде выполнения Go (она в библиотеке ядра)")
    return f"уведомления — {len(expected)} компонентов матрицы с текстами лицензий"


def main():
    a = argparse.ArgumentParser(description="Проверка собранного APK")
    a.add_argument("apk", nargs="?", default=APK)
    a.add_argument("--abi", choices=sorted(native.ABIS), help="APK одного ABI (D-28, D-35)")
    args = a.parse_args()
    apk = args.apk
    if not os.path.isfile(apk):
        print(f"✗ check_apk: нет {os.path.relpath(apk, PROJ)} — сначала ./gradlew :app:assembleDebug")
        return 2
    sdk = sdk_dir()
    tools = build_tools(sdk) if sdk else None
    if not tools:
        print("✗ check_apk: нет build-tools Android SDK с aapt2 и dexdump (ANDROID_HOME или sdk.dir в local.properties)")
        return 2
    problems = []

    # ---- итоговый манифест ----
    root = manifest_tree(os.path.join(tools, "aapt2"), apk)
    package = root.get("package", "")
    app = root.find("application")
    declared = {p.get(A + "name") for p in root.iter("uses-permission")} | {
        p.get(A + "name") for p in root.iter("uses-permission-sdk-23")}
    for p in sorted(declared - set(PERMISSIONS)):
        problems.append(f"манифест APK: разрешение {p} не утверждено — пришло из зависимости? (список — check_manifest.py)")
    for p in sorted(set(PERMISSIONS) - declared):
        problems.append(f"манифест APK: нет разрешения {p}")
    if app is None:
        problems.append("манифест APK: нет <application>")
    else:
        for attr, want in (("allowBackup", "false"), ("fullBackupContent", "false"), ("usesCleartextTraffic", "false")):
            if app.get(A + attr) != want:
                problems.append(f"манифест APK: android:{attr} = {app.get(A + attr)}, нужно {want}")
        for attr in ("networkSecurityConfig", "dataExtractionRules"):
            if not app.get(A + attr):
                problems.append(f"манифест APK: нет android:{attr}")
        if app.get(A + "process") is not None:
            problems.append("манифест APK: <application android:process> — приложение работает в одном процессе (D-30)")

        # Имена компонентов, относительные (.app.X), AGP раскрывает по
        # пространству имён кода, не по applicationId: у личной сборки они
        # различаются (D-47). Поэтому раскрываем по namespace, не по package.
        def full(name):
            return NAMESPACE + name if name.startswith(".") else name

        source = ET.parse(SOURCE_MANIFEST).getroot().find("application")
        own = {full(el.get(A + "name")) for el in source} if source is not None else set()
        exported_ok = {full(n) for n in EXPORTED_OK}
        for el in app:
            if el.tag not in ("activity", "activity-alias", "service", "receiver", "provider"):
                continue
            name = full(el.get(A + "name", ""))
            if el.get(A + "process") is not None:
                problems.append(f"манифест APK: <{el.tag} {name}> android:process — компоненты в процессе приложения (D-30)")
            if name not in own:
                problems.append(f"манифест APK: <{el.tag} {name}> не объявлен в исходном манифесте — добавлен зависимостью")
            if el.get(A + "exported") == "true":
                if name not in exported_ok:
                    problems.append(f"манифест APK: <{el.tag} {name}> экспортирован без причины")
                if el.tag in ("service", "receiver", "provider") and not el.get(A + "permission"):
                    problems.append(f"манифест APK: <{el.tag} {name}> экспортирован без android:permission")
            actions = {a.get(A + "name") for f in el.iter("intent-filter") for a in f.iter("action")}
            if "android.net.VpnService" in actions:
                if el.get(A + "permission") != "android.permission.BIND_VPN_SERVICE":
                    problems.append(f"манифест APK: {name} — VpnService без BIND_VPN_SERVICE")
                fgs = el.get(A + "foregroundServiceType", "0")
                if not int(fgs, 16 if fgs.startswith("0x") else 10) & SPECIAL_USE:
                    problems.append(f"манифест APK: {name} — тип foreground-сервиса не specialUse (D-17)")

    # ---- код ----
    classes = dex_classes(os.path.join(tools, "dexdump"), apk)
    by_root = {}
    for desc, synthetic in classes:
        test_only = next((what for prefix, what in TEST_ONLY_CODE.items() if desc.startswith(prefix)), None)
        if test_only:
            problems.append(f"dex: класс {desc.replace('/', '.')} — {test_only}, тестовая фикстура; в APK ей не место")
            continue
        root_ok = next((r for r in CODE_ROOTS if desc.startswith(r)), None)
        if root_ok:
            by_root[root_ok] = by_root.get(root_ok, 0) + 1
        elif desc.startswith(SYNTHETIC_ONLY_ROOTS) and synthetic:
            by_root["заглушки платформы (D8)"] = by_root.get("заглушки платформы (D8)", 0) + 1
        else:
            problems.append(f"dex: класс {desc.replace('/', '.')} — не из утверждённых корней "
                            "(свой код и компоненты матрицы лицензий; новый корень — с причиной в check_apk.py)")
    if not classes:
        problems.append("dex: в APK не найдено ни одного класса")

    # ---- нативные библиотеки и размер ----
    native_sizes = check_natives(apk, problems, args.abi)
    geodata = check_geodata(apk, problems)
    legal = check_notices(apk, problems)
    size = os.path.getsize(apk)
    per_abi, holes = abi_apk_sizes(apk)
    for abi, n in sorted(per_abi.items()):
        if n > ABI_APK_BUDGET_MIB * 1024 * 1024:
            problems.append(f"APK для {abi} — {n / 1024 / 1024:.1f} МиБ, предел {ABI_APK_BUDGET_MIB} МиБ "
                            "(D-28; новое значение — с замером, docs/PERFORMANCE_BUDGET.md, §4)")
    abi_sizes = ", ".join(f"{abi} {n / 1024 / 1024:.1f}" for abi, n in sorted(per_abi.items()))

    if problems:
        print("✗ APK:")
        for p in problems[:60]:
            print("    " + p)
        if len(problems) > 60:
            print(f"    … и ещё {len(problems) - 60}")
        return 1
    roots = ", ".join(f"{r.rstrip('/').replace('/', '.')} {n}" for r, n in sorted(by_root.items(), key=lambda kv: -kv[1]))
    print(f"✓ APK {os.path.relpath(apk, PROJ)}: {size / 1024 / 1024:.1f} МиБ; манифест — утверждённые разрешения и компоненты; "
          f"{len(classes)} классов только из утверждённых корней ({roots}); "
          f"нативный код — только {native.LIBRARY} ({native_sizes}), несжатая, выровнена по 16 КБ в zip и ELF, экспорт JNI = XrayJni; "
          f"{geodata}; {legal}; "
          f"APK одного ABI (D-28) — {abi_sizes} МиБ, предел {ABI_APK_BUDGET_MIB}"
          + (f"; пустоты пошаговой упаковки AGP — {holes / 1024 / 1024:.1f} МиБ, в оценку не входят" if holes > 1024 * 1024 else ""))
    return 0


if __name__ == "__main__":
    sys.exit(main())
