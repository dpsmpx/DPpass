#!/usr/bin/env python3
"""Уведомления о сторонних компонентах в APK (D-43) — из матрицы лицензий.

    python3 tools/legal/notices.py [--out DIR]
        DIR/notices/NOTICES.txt (по умолчанию DIR = build/legal)
    python3 tools/legal/notices.py --list
        какие компоненты должны быть в уведомлениях (для check_apk.py)

Состав — то, что матрица (`docs/legal/THIRD_PARTY_MATRIX.md`) называет
попадающим в APK:

  * §1.1 — строки, у которых «Куда» содержит «APK» (Kotlin, корутины);
  * §1.6 — ядро Xray (MPL-2.0: где взять исходник этой версии);
  * §1.7 — модули Go библиотеки ядра, кроме «в сборку не входит»;
  * §1.8 — геоданные (их уведомления — `assets/geodata/NOTICE.txt`, его
    пишет сборщик набора; здесь — ссылка на него);
  * среда выполнения Go — статически в библиотеке ядра (§1.5): `LICENSE`
    из `GOROOT` той версии Go, что собирает ядро.

Тексты лицензий модулей Go — из `LICENSE` в архиве модуля той версии,
что закреплена в `tools/xray/go.sum` (`go mod download` со сверкой
sum.golang.org, `goenv.py`, T10). Одинаковые тексты — один раз, с
номером. Для библиотек Kotlin (Apache-2.0) — тот же текст Apache-2.0 из
модуля Go с этой лицензией.

Комплект Windows (D-97, `tools/desktop/windows_package.py`) зовёт
`build(out, jars)`: библиотеки Maven — только с jar комплекта, а
сторонний jar без строки §1.1 — отказ.

Код возврата: 0 — готово; 1 — нет строки в матрице, текста лицензии или
архива модуля; 3 — нет Go.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.path.insert(0, os.path.join(PROJ, "tools", "xray"))
import goenv  # noqa: E402

MATRIX = os.path.join(PROJ, "docs", "legal", "THIRD_PARTY_MATRIX.md")
TOOL = os.path.join(PROJ, "tools", "xray")
DEFAULT_OUT = os.path.join(PROJ, "build", "legal")
SET_DIR = "notices"
FILE = "NOTICES.txt"
LICENSE_NAMES = ("LICENSE", "LICENSE.txt", "LICENSE.md", "LICENCE", "COPYING", "LICENSE-APACHE")
XRAY_SOURCE = "https://github.com/XTLS/Xray-core/tree/v{version}"
# NOTICE библиотек Apache-2.0 (§4(d) лицензии): строки об авторских правах из
# NOTICE проекта на теге той версии, что в каталоге (docs/PROVENANCE.md).
# Версия сменилась — NOTICE сверяется заново, иначе уведомления не собираются.
MAVEN_NOTICES = {
    "com.google.zxing:core": ("3.5.4", (
        "NOTICE ZXing (github.com/zxing/zxing, тег zxing-3.5.4):",
        "Barcode4J — Copyright 2002-2010 Jeremias Märki, Copyright 2005-2006 Dietmar Bürkle;",
        "portions of this software were contributed under section 5 of the Apache License,",
        "contributors: http://barcode4j.sourceforge.net/contributors.html.",
        "JCommander — Copyright 2010 Cedric Beust cedric@beust.com.",
    )),
}


class Missing(Exception):
    """Нет Go — тексты лицензий модулей не получить (код 3)."""


def section(text, number):
    """Строки раздела `### number.` до следующего заголовка."""
    out, inside = [], False
    for line in text.splitlines():
        if line.startswith("### ") or line.startswith("## "):
            inside = line.startswith(f"### {number}.")
            continue
        if inside:
            out.append(line)
    return out


def table(lines):
    """Строки таблицы Markdown (без шапки и разделителя) — списки ячеек."""
    rows = [ln for ln in lines if ln.startswith("|")]
    out = []
    for ln in rows[2:]:
        out.append([c.strip() for c in ln.strip().strip("|").split("|")])
    return out


def code(cell):
    """Первое значение в обратных кавычках или сама ячейка."""
    m = re.search(r"`([^`]+)`", cell)
    return m.group(1) if m else cell


def components():
    """Компоненты APK из матрицы: (вид, имя, версия, лицензия)."""
    with open(MATRIX, encoding="utf-8") as f:
        text = f.read()
    out = []
    for name, version, license_, where, *_ in table(section(text, "1.1")):
        if "APK" in where:
            out.append(("maven", code(name), version, license_))
    for name, version, license_, where, *_ in table(section(text, "1.6")):
        out.append(("xray", code(name), version, license_))
    for name, version, license_, used, *_ in table(section(text, "1.7")):
        if "в сборку не входит" in used:
            continue
        out.append(("go", code(name), code(version), license_))
    for name, version, license_, where, *_ in table(section(text, "1.8")):
        out.append(("data", code(name), code(version), license_))
    if not any(k == "xray" for k, *_ in out) or not any(k == "go" for k, *_ in out):
        raise SystemExit("✗ notices: в матрице нет ядра (§1.6) или модулей Go (§1.7)")
    return out


def escape(path):
    """Путь модуля Go в кеше модулей: заглавная буква → «!» и строчная."""
    return re.sub(r"[A-Z]", lambda m: "!" + m.group(0).lower(), path)


def module_dir(module, version, env):
    r = subprocess.run(["go", "mod", "download", "-json", f"{module}@{version}"], cwd=TOOL, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        raise SystemExit(f"✗ notices: go mod download {module}@{version}: {r.stderr.strip()[-300:]}")
    return json.loads(r.stdout)["Dir"]


def license_text(directory):
    for n in LICENSE_NAMES:
        p = os.path.join(directory, n)
        if os.path.isfile(p):
            with open(p, encoding="utf-8", errors="replace") as f:
                return f.read().strip() + "\n"
    return None


def only_jars(items, jars):
    """Библиотеки Maven — только те, чьи jar в комплекте (оболочка ПК, D-97); сторонний jar без строки матрицы — отказ."""
    maven = [(k, n, v, lic) for k, n, v, lic in items if k == "maven"]

    def artifact(name):
        return name.split(":")[1]

    stray = [j for j in jars if re.search(r"-\d[^/]*\.jar$", j) and not any(j.startswith(artifact(n) + "-") for _, n, _, _ in maven)]
    if stray:
        raise SystemExit(f"✗ notices: jar без строки в матрице лицензий (§1.1): {', '.join(stray)}")
    return [i for i in items if i[0] != "maven" or any(j.startswith(artifact(i[1]) + "-") for j in jars)]


def build(out_dir, jars=None):
    """[jars] — имена jar комплекта: библиотеки Maven — только из них (без него — все строки APK)."""
    if shutil.which("go") is None:
        raise Missing()
    env = goenv.go_env()
    items = components()
    if jars is not None:
        items = only_jars(items, jars)
    texts = {}  # sha → (номер, текст)
    entries = []
    apache = None

    def number(t):
        h = hashlib.sha256(t.encode()).hexdigest()
        if h not in texts:
            texts[h] = (len(texts) + 1, t)
        return texts[h][0]

    for kind, name, version, license_ in items:
        if kind not in ("go", "xray"):
            continue
        module = name if kind == "go" else "github.com/xtls/xray-core"
        mod_version = version
        if kind == "xray":
            # Версия модуля ядра — из §1.7 (псевдоверсия для тега).
            mod_version = next(v for k, n, v, _ in items if k == "go" and n == module)
        t = license_text(module_dir(module, mod_version, env))
        if t is None:
            raise SystemExit(f"✗ notices: у {module}@{mod_version} нет файла лицензии в архиве модуля")
        if "Apache License" in t and "Version 2.0" in t and apache is None:
            apache = t
        if kind == "xray":
            continue
        entries.append((name, version, license_, number(t), None))
    if apache is None:
        raise SystemExit("✗ notices: нет текста Apache-2.0 среди модулей Go — нечем снабдить библиотеки Kotlin")

    head = []
    for kind, name, version, license_ in items:
        if kind == "maven":
            note = None
            if name in MAVEN_NOTICES:
                want, notice = MAVEN_NOTICES[name]
                if version != want:
                    raise SystemExit(f"✗ notices: {name} {version}: NOTICE сверен для {want} — сверить NOTICE новой версии (D-18)")
                note = "\n  ".join(notice)
            head.append((name, version, license_, number(apache) if "Apache-2.0" in license_ else None, note))
        elif kind == "xray":
            mod_version = next(v for k, n, v, _ in items if k == "go" and n == "github.com/xtls/xray-core")
            t = license_text(module_dir("github.com/xtls/xray-core", mod_version, env))
            head.append((name, version, license_, number(t), "исходный код этой версии: " + XRAY_SOURCE.format(version=version)))
    # Среда выполнения Go статически входит в библиотеку ядра (матрица, §1.5): её лицензия — тоже.
    goroot = subprocess.run(["go", "env", "GOROOT"], cwd=TOOL, env=env, capture_output=True, text=True).stdout.strip()
    goversion = subprocess.run(["go", "env", "GOVERSION"], cwd=TOOL, env=env, capture_output=True, text=True).stdout.strip()
    runtime_text = license_text(goroot) if goroot else None
    if runtime_text is None:
        raise SystemExit("✗ notices: нет LICENSE в GOROOT — лицензию среды выполнения Go не взять")
    head.append(("Go (среда выполнения)", goversion, "BSD-3-Clause", number(runtime_text), None))
    data = [(name, version, license_) for kind, name, version, license_ in items if kind == "data"]

    lines = [
        "DPpass — уведомления о сторонних компонентах",
        "",
        "Собрано из docs/legal/THIRD_PARTY_MATRIX.md (D-43): всё, что входит в это приложение,",
        "с лицензией и текстом лицензии. Тексты — из архивов модулей тех версий, что в сборке.",
        "",
        "== Приложение и ядро ==",
        "",
    ]
    for name, version, license_, n, note in head + entries:
        lines.append(f"* {name} {version} — {license_}" + (f"; текст [{n}]" if n else ""))
        if note:
            lines.append(f"  {note}")
    lines += ["", "== Геоданные ==", ""]
    for name, version, license_ in data:
        lines.append(f"* {name} {version} — {license_}")
    lines += [
        "  IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0; уведомления набора — geodata/NOTICE.txt",
        "",
        "== Тексты лицензий ==",
        "",
    ]
    for n, t in sorted(texts.values()):
        lines += [f"--- [{n}] ---", t]
    target = os.path.join(out_dir, SET_DIR)
    os.makedirs(target, exist_ok=True)
    path = os.path.join(target, FILE)
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    print(f"✓ уведомления: {len(head) + len(entries)} компонентов, {len(data)} источника геоданных, {len(texts)} текстов лицензий — {os.path.relpath(path, PROJ)}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default=DEFAULT_OUT)
    ap.add_argument("--list", action="store_true")
    a = ap.parse_args()
    if a.list:
        for kind, name, version, license_ in components():
            print(f"{kind}\t{name}\t{version}\t{license_}")
        return 0
    try:
        build(a.out)
    except Missing:
        print("✗ notices: нет Go — тексты лицензий модулей ядра не получить")
        return 3
    except goenv.UnsafeGoEnv as e:
        print(f"✗ notices: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
