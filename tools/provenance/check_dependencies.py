#!/usr/bin/env python3
"""Ядро прокси, модули Go, суммы артефактов Gradle и геоданные — с лицензией и происхождением (D-18, D-20).

Строки каталога Gradle и версии Gradle в матрице и PROVENANCE, SHA-256
дистрибутива, двоичные файлы, координаты и репозитории мимо каталога,
workflow CI проверяет DP Verify (D-50): `provenance.deps`,
`provenance.binaries`, `code.forbidden` (`inline-coordinates`,
`repositories`), `repo.layout` (`tools/dpverify.toml`). Здесь — то, чего у
DP Verify нет:

  * ядро прокси и его сборка на хосте (D-24): `tools/xray/go.mod` требует
    Xray той версии, что в каталоге (`xray-go-module`), каждый модуль
    `require` — строка матрицы с той же версией и строка PROVENANCE с
    той же версией и суммой `h1:` из `go.sum`; строки модулей, которых
    в `go.mod` больше нет, — тоже ошибка; toolchain Go из директивы `go`
    записан; `replace` и неизвестные директивы запрещены (подмена
    модуля форком прошла бы мимо записей);
  * содержимое артефактов Gradle сверяется (T10, аудит A-7):
    `gradle/verification-metadata.xml` есть, проверка включена, у каждого
    артефакта — SHA-256, доверие без сумм — только javadoc и исходники
    (их качает IDE), у каждой библиотеки каталога — суммы той же версии
    (`tools/provenance/update_verification.sh`);
  * `kotlin("test")` — строка матрицы с версией Kotlin (версию задаёт
    плагин, а не каталог);
  * источники геоданных (D-27, D-31): версии `geodata-dlc` и `geodata-dbip`
    из каталога — строки матрицы («разрешён») и PROVENANCE (§2 «Геоданные»:
    версия и сумма `h1:` модуля dlc; выпуск DB-IP); файл выпуска DB-IP —
    в `tools/xray/geodata/sources/`, других файлов там нет;
  * архивы оболочки Windows (D-97): версии `temurin-windows` и `wintun` из
    каталога — строки матрицы («разрешён») и PROVENANCE (§2 «Windows»:
    имя архива этой версии с одной суммой SHA-256 — по ней сверяет
    `tools/desktop/windows_deps.py`).

    python3 tools/provenance/check_dependencies.py

Код возврата: 0 — чисто; 1 — расхождения.
"""
import os
import re
import sys
import tomllib
import xml.etree.ElementTree as ET

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(PROJ, "gradle", "libs.versions.toml")
MATRIX = os.path.join(PROJ, "docs", "legal", "THIRD_PARTY_MATRIX.md")
PROVENANCE = os.path.join(PROJ, "docs", "PROVENANCE.md")
VERIFICATION = os.path.join(PROJ, "gradle", "verification-metadata.xml")
VERIFICATION_NS = "{https://schema.gradle.org/dependency-verification}"
# Доверие без сумм — только то, что сборка не берёт (javadoc и исходники для IDE).
TRUSTED_WITHOUT_SUMS = {".*-javadoc[.]jar", ".*-sources[.]jar"}
GOMOD = os.path.join(PROJ, "tools", "xray", "go.mod")
GOSUM = os.path.join(PROJ, "tools", "xray", "go.sum")
XRAY_MODULE = "github.com/xtls/xray-core"
DLC_MODULE = "github.com/v2fly/domain-list-community"
GEODATA_SOURCES = os.path.join(PROJ, "tools", "xray", "geodata", "sources")
# Директивы go.mod, которые проверка понимает; любая другая (replace, exclude,
# retract, godebug, …) меняет то, что соберётся, мимо записей — ошибка.
GOMOD_DIRECTIVES = {"module", "go", "toolchain", "require", "tool"}
# Версия задаётся не каталогом, а самим плагином Kotlin — и потому совпадает с ним.
IMPLICIT = {'kotlin("test")': ("org.jetbrains.kotlin:kotlin-test", "kotlin")}


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def table_rows(text):
    return [line for line in text.splitlines() if line.lstrip().startswith("|")]


def row_with(rows, coord):
    needle = f"`{coord}`"
    return [r for r in rows if needle in r]


def parse_gomod(text):
    """Директивы go.mod: {имя: [аргументы, …]}; блоки «директива ( … )» раскрываются."""
    out = {}
    block = None
    for raw in re.sub(r"//[^\n]*", "", text).splitlines():
        line = raw.strip()
        if not line:
            continue
        if block is not None:
            if line == ")":
                block = None
                continue
            name, args = block, line
        else:
            name, _, args = line.partition(" ")
            args = args.strip()
            if args == "(":
                block = name
                out.setdefault(name, [])
                continue
        out.setdefault(name, []).append(args)
    return out


def section_rows(text, marker):
    """Строки таблиц раздела, заголовок которого содержит marker (до следующего заголовка)."""
    rows, inside = [], False
    for line in text.splitlines():
        if line.startswith("#"):
            inside = marker in line
        elif inside and line.lstrip().startswith("|"):
            rows.append(line)
    return rows


def has_version(rows, ver):
    return any(re.search(r"(?<![\w.])" + re.escape(ver) + r"(?![\w.])", r) for r in rows)


def check_geodata(versions, mrows, provenance, problems):
    """Источники набора геоданных (D-27, D-31): каталог ↔ матрица, PROVENANCE, файл DB-IP."""
    dlc, dbip = versions.get("geodata-dlc"), versions.get("geodata-dbip")
    if not dlc or not dbip:
        problems.append("libs.versions.toml: нет версий geodata-dlc и geodata-dbip (источники геоданных закрепляются в каталоге, D-27)")
        return
    grows = section_rows(provenance, "Геоданные")
    if not any(has_version([r], dlc) and "разрешён" in r for r in row_with(mrows, DLC_MODULE)):
        problems.append(f"THIRD_PARTY_MATRIX.md: нет строки `{DLC_MODULE}` с версией {dlc} и статусом «разрешён»")
    if not any(re.search(r"`h1:[A-Za-z0-9+/=]+`", r) for r in row_with(grows, DLC_MODULE) if f"`{dlc}`" in r):
        problems.append(f"PROVENANCE.md, «Геоданные»: нет строки `{DLC_MODULE}` `{dlc}` с суммой h1 архива")
    if not any("DB-IP" in r and f"`{dbip}`" in r and "разрешён" in r for r in mrows):
        problems.append(f"THIRD_PARTY_MATRIX.md: нет строки DB-IP с выпуском `{dbip}` и статусом «разрешён»")
    if not any("DB-IP" in r and f"`{dbip}`" in r for r in grows):
        problems.append(f"PROVENANCE.md, «Геоданные»: нет строки DB-IP с выпуском `{dbip}`")
    want = f"dbip-country-lite-{dbip}.csv.gz"
    present = sorted(os.listdir(GEODATA_SOURCES)) if os.path.isdir(GEODATA_SOURCES) else []
    if want not in present:
        problems.append(f"tools/xray/geodata/sources/{want}: нет файла выпуска DB-IP {dbip} из каталога (D-31)")
    for name in present:
        if name != want:
            problems.append(f"tools/xray/geodata/sources/{name}: источник не из каталога (устарел?) — "
                            "в наборе только закреплённый выпуск")


def check_windows(versions, mrows, provenance, problems):
    """Архивы оболочки Windows (D-97): каталог ↔ матрица и PROVENANCE с суммой того архива,
    который скачивает windows_deps.py."""
    sys.path.insert(0, os.path.join(PROJ, "tools", "desktop"))
    import windows_deps  # noqa: E402 — те же имена архивов, что при сборке

    wrows = section_rows(provenance, "Windows")
    for name, key, label in (("temurin", "temurin-windows", "Eclipse Temurin JDK 21"), ("wintun", "wintun", "Wintun")):
        ver = versions.get(key)
        if not ver:
            problems.append(f"libs.versions.toml: нет версии {key} (архивы Windows закрепляются в каталоге, D-97)")
            continue
        try:
            file, _ = windows_deps.archive(name, ver)
        except RuntimeError as e:
            problems.append(f"libs.versions.toml: {e}")
            continue
        if not any(label in r and f"`{ver}`" in r and "разрешён" in r for r in mrows):
            problems.append(f"THIRD_PARTY_MATRIX.md: нет строки «{label}» с версией `{ver}` и статусом «разрешён»")
        rows = [r for r in wrows if f"`{file}`" in r and f"`{ver}`" in r]
        if len({m for r in rows for m in re.findall(r"`([0-9a-f]{64})`", r)}) != 1:
            problems.append(f"PROVENANCE.md, «Windows»: нет строки `{file}` версии `{ver}` с одной суммой SHA-256")


def check_go(versions, matrix, mrows, prows, problems):
    """Ядро прокси и модули Go его сборки на хосте (D-24): go.mod ↔ каталог, матрица, PROVENANCE."""
    if not os.path.isfile(GOMOD):
        problems.append("нет tools/xray/go.mod — ядро для проверки на хосте не собрать (D-24)")
        return 0
    mod = parse_gomod(read(GOMOD))
    for name in sorted(set(mod) - GOMOD_DIRECTIVES):
        problems.append(f"tools/xray/go.mod: директива {name} — запрещена или не разобрана проверкой "
                        "(подмена модуля прошла бы мимо матрицы и PROVENANCE)")
    sums = {}
    if os.path.isfile(GOSUM):
        for line in read(GOSUM).splitlines():
            parts = line.split()
            if len(parts) == 3 and not parts[1].endswith("/go.mod"):
                sums[(parts[0], parts[1])] = parts[2]
    else:
        problems.append("нет tools/xray/go.sum — суммы модулей Go не закреплены")

    requires = {}
    for args in mod.get("require", []):
        parts = args.split()
        if len(parts) < 2:
            problems.append(f"tools/xray/go.mod: не разобрано «require {args}»")
            continue
        requires[parts[0]] = parts[1]

    want_xray, want_module = versions.get("xray"), versions.get("xray-go-module")
    if not want_xray or not want_module:
        problems.append("libs.versions.toml: нет версий xray и xray-go-module (ядро закрепляется в каталоге, D-18)")
    elif requires.get(XRAY_MODULE) != want_module:
        problems.append(f"tools/xray/go.mod: {XRAY_MODULE} {requires.get(XRAY_MODULE)}, а в каталоге "
                        f"xray-go-module = {want_module} — ядро разошлось с каталогом")
    else:
        if not has_version(row_with(mrows, "XTLS/Xray-core"), want_xray):
            problems.append(f"THIRD_PARTY_MATRIX.md: нет строки `XTLS/Xray-core` с версией {want_xray}")
        core_rows = [r for r in prows if r.lstrip().startswith("| Xray-core |")]
        if not (has_version(core_rows, want_xray) and has_version(core_rows, want_module)):
            problems.append(f"PROVENANCE.md: строка «Xray-core» не с версией {want_xray} и модулем {want_module}")

    for args in mod.get("go", []) + mod.get("toolchain", []):
        ver = args.split()[0]
        ver = ver if ver.startswith("go") else "go" + ver
        if not has_version(row_with(prows, "golang.org/toolchain"), ver):
            problems.append(f"PROVENANCE.md: нет строки `golang.org/toolchain` с {ver} (tools/xray/go.mod)")
        if not has_version([r for r in mrows if "Go " in r], ver):
            problems.append(f"THIRD_PARTY_MATRIX.md: в строке Go нет toolchain {ver} (tools/xray/go.mod)")

    for path, ver in sorted(requires.items()):
        if not has_version(row_with(mrows, path), ver):
            problems.append(f"THIRD_PARTY_MATRIX.md: нет строки `{path}` с версией {ver} (tools/xray/go.mod)")
        h1 = sums.get((path, ver))
        if h1 is None:
            problems.append(f"tools/xray/go.sum: нет суммы {path} {ver}")
            continue
        found = row_with(prows, path)
        if not any(has_version([r], ver) and f"`{h1}`" in r for r in found):
            problems.append(f"PROVENANCE.md: нет строки `{path}` с версией {ver} и суммой {h1} из go.sum")

    # Строки модулей, которых в go.mod больше нет: запись о том, чего не собирается, вводит в заблуждение.
    module_ref = re.compile(r"^\|\s*`([^`]+)`")
    # Источники геоданных — не модули сборки (у dlc тоже сумма h1): их сверяет check_geodata.
    geodata_rows = set(section_rows(read(PROVENANCE), "Геоданные")) if os.path.isfile(PROVENANCE) else set()
    for name, rows in (("THIRD_PARTY_MATRIX.md", section_rows(matrix, "`tools/xray`")),
                       ("PROVENANCE.md", [r for r in prows if "`h1:" in r and r not in geodata_rows])):
        for r in rows:
            m = module_ref.match(r.strip())
            if m and "/" in m.group(1) and m.group(1) not in requires:
                problems.append(f"{name}: строка `{m.group(1)}` — такого модуля в tools/xray/go.mod нет (устарела)")
    return len(requires)


def check_verification(resolved, problems):
    """Суммы артефактов Gradle (T10, аудит A-7); resolved — [(где, группа:имя, версия)] библиотек каталога. Возвращает число компонентов."""
    rel = os.path.relpath(VERIFICATION, PROJ)
    if not os.path.isfile(VERIFICATION):
        problems.append(f"нет {rel}: содержимое артефактов Gradle не сверяется (T10) — tools/provenance/update_verification.sh")
        return 0
    try:
        root = ET.parse(VERIFICATION).getroot()
    except ET.ParseError as e:
        problems.append(f"{rel}: не XML ({e})")
        return 0
    v = VERIFICATION_NS
    conf = root.find(v + "configuration")
    if conf is None or (conf.findtext(v + "verify-metadata") or "").strip() != "true":
        problems.append(f"{rel}: verify-metadata не true — суммы записаны, но не сверяются")
    for t in (conf.iter(v + "trust") if conf is not None else ()):
        if not (t.get("regex") == "true" and t.get("file") in TRUSTED_WITHOUT_SUMS and set(t.attrib) == {"file", "regex"}):
            problems.append(f"{rel}: доверие без сумм {dict(t.attrib)} — допустимы только javadoc и исходники")
    components = {}
    for c in root.iter(v + "component"):
        components[(c.get("group"), c.get("name"), c.get("version"))] = c
        for a in c.iter(v + "artifact"):
            if a.find(v + "sha256") is None:
                problems.append(f"{rel}: {c.get('group')}:{c.get('name')}:{c.get('version')} {a.get('name')} — без SHA-256")
    for where, coord, ver in resolved:
        group, name = coord.split(":", 1)
        if (group, name, ver) not in components:
            problems.append(f"{rel}: нет сумм {group}:{name}:{ver} ({where}) — tools/provenance/update_verification.sh")
    return len(components)


def main():
    problems = []
    with open(CATALOG, "rb") as f:
        catalog = tomllib.load(f)
    versions = catalog.get("versions", {})
    matrix = read(MATRIX) if os.path.isfile(MATRIX) else ""
    provenance = read(PROVENANCE) if os.path.isfile(PROVENANCE) else ""
    if not matrix:
        problems.append("нет docs/legal/THIRD_PARTY_MATRIX.md")
    if not provenance:
        problems.append("нет docs/PROVENANCE.md")
    mrows, prows = table_rows(matrix), table_rows(provenance)

    def version_of(entry):
        if isinstance(entry, str):
            return entry.rsplit(":", 1)[1] if entry.count(":") == 2 else None
        v = entry.get("version")
        if isinstance(v, dict):
            return versions.get(v.get("ref")) if "ref" in v else v.get("strictly") or v.get("require")
        if isinstance(v, str):
            return v
        return versions.get(entry["version.ref"]) if "version.ref" in entry else None

    boms = {}
    entries = []
    for alias, lib in catalog.get("libraries", {}).items():
        coord = lib if isinstance(lib, str) and lib.count(":") >= 1 else lib.get("module") or f"{lib['group']}:{lib['name']}"
        coord = ":".join(coord.split(":")[:2])
        ver = version_of(lib)
        if coord.endswith("-bom") and ver:
            boms[coord.rsplit(":", 1)[0]] = ver
        entries.append((f"libraries.{alias}", coord, ver))
    for alias, plugin in catalog.get("plugins", {}).items():
        pid = plugin if isinstance(plugin, str) else plugin["id"]
        entries.append((f"plugins.{alias}", pid.split(":")[0], version_of(plugin)))

    resolved = []
    for where, coord, ver in entries:
        if ver is None:
            # Версия — из BOM той же группы (junit-bom → junit-jupiter).
            group = coord.split(":")[0]
            ver = next((v for g, v in boms.items() if group == g or group.startswith(g + ".")), None)
            if ver is None:
                problems.append(f"libs.versions.toml {where}: {coord} без версии и без BOM своей группы")
                continue
        # Маркеры плагинов сборка не берёт: плагины приходят в build-logic библиотеками каталога.
        # Строки матрицы и PROVENANCE для каталога сверяет provenance.deps (D-50).
        if where.startswith("libraries."):
            resolved.append((where, coord, ver))

    verified = check_verification(resolved, problems)
    go_modules = check_go(versions, matrix, mrows, prows, problems)
    check_geodata(versions, mrows, provenance, problems)
    check_windows(versions, mrows, provenance, problems)

    for call, (coord, vref) in IMPLICIT.items():
        ver = versions.get(vref)
        if not any(ver in r for r in row_with(mrows, coord)):
            problems.append(f"THIRD_PARTY_MATRIX.md: нет строки `{coord}` {ver} (подключается как {call})")

    if problems:
        print("✗ Зависимости и происхождение:")
        for p in problems:
            print("    " + p)
        print("  Новая зависимость или версия — по чек-листу D-18 вместе со строками THIRD_PARTY_MATRIX.md и PROVENANCE.md (docs/PROCESS.md).")
        return 1
    print(f"✓ Зависимости: {go_modules} модулей Go (tools/xray, Xray {versions.get('xray')}) и kotlin(\"test\") "
          f"сверены с матрицей лицензий и PROVENANCE.md; геоданные — dlc {versions.get('geodata-dlc')} и DB-IP {versions.get('geodata-dbip')}; "
          f"артефакты Gradle — по SHA-256 ({verified} компонентов в verification-metadata.xml)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
