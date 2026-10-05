#!/usr/bin/env python3
"""Набор геоданных DPpass (D-27, D-31) — из закреплённых источников своим сборщиком.

    python3 tools/xray/geodata.py [--out DIR] [--test]

Источники — версии из каталога (`gradle/libs.versions.toml`: `geodata-dlc`,
`geodata-dbip`), суммы — из `docs/PROVENANCE.md` (§2 «Геоданные», §4):

  * dlc — Go-модуль `github.com/v2fly/domain-list-community` той версии:
    `go mod download` с proxy.golang.org со сверкой sum.golang.org
    (`goenv.py`, T10); сумма `h1:` архива должна совпасть с записанной;
  * DB-IP «IP to Country Lite» — файл выпуска в репозитории
    (`tools/xray/geodata/sources/`): DB-IP хранит на сайте только последние
    выпуски (D-31); SHA-256 должна совпасть с записанной.

Сборщик — `tools/xray/geodata` (Go, тот же `go.mod`, что у ядра). Набор —
`DIR/geodata/` (geoip.dat, geosite.dat, NOTICE.txt, manifest.json); DIR по
умолчанию — `build/xray/geodata-set`. Раскладка — как в assets APK
(`geodata/…`): так его кладёт задача :app `xrayGeodata<Вариант>` и читает
`engine.xray.GeodataInstaller`; `check_apk.py` сверяет набор в APK с
набором этого шага.

--test: сначала go vet и go test сборщика, а собранный набор целиком
загружает ядро Xray закреплённой версии (каждый код; шаг hostcheck
«Xray: геоданные»).

Код возврата: 0 — набор собран; 1 — ошибка источников или сборки; 3 — нет Go.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tomllib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import goenv  # noqa: E402

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TOOL = os.path.join(PROJ, "tools", "xray")
CATALOG = os.path.join(PROJ, "gradle", "libs.versions.toml")
PROVENANCE = os.path.join(PROJ, "docs", "PROVENANCE.md")
SOURCES = os.path.join(TOOL, "geodata", "sources")
DEFAULT_OUT = os.path.join(PROJ, "build", "xray", "geodata-set")
BUILDER = os.path.join(PROJ, "build", "xray", "dppass-geodata")
DLC_MODULE = "github.com/v2fly/domain-list-community"
SET_DIR = "geodata"


class Missing(Exception):
    """Нет Go — набор не собрать (код 3)."""


def rel(path):
    return os.path.relpath(path, PROJ)


def dbip_file(release):
    return os.path.join(SOURCES, f"dbip-country-lite-{release}.csv.gz")


def pinned():
    """(версия dlc, выпуск DB-IP) из каталога."""
    with open(CATALOG, "rb") as f:
        versions = tomllib.load(f).get("versions", {})
    dlc, dbip = versions.get("geodata-dlc"), versions.get("geodata-dbip")
    if not dlc or not dbip:
        raise RuntimeError("libs.versions.toml: нет версий geodata-dlc и geodata-dbip (источники закрепляются в каталоге, D-27)")
    return dlc, dbip


def recorded_sums(dlc, dbip_rel):
    """Суммы из PROVENANCE.md: h1 архива dlc этой версии и SHA-256 файла DB-IP."""
    with open(PROVENANCE, encoding="utf-8") as f:
        rows = [line for line in f.read().splitlines() if line.lstrip().startswith("|")]
    h1 = None
    for r in rows:
        if f"`{DLC_MODULE}`" in r and f"`{dlc}`" in r:
            m = re.search(r"`(h1:[A-Za-z0-9+/=]+)`", r)
            h1 = m.group(1) if m else None
    sha = None
    for r in rows:
        if f"`{dbip_rel}`" in r:
            m = re.search(r"`([0-9a-f]{64})`", r)
            sha = m.group(1) if m else None
    if h1 is None:
        raise RuntimeError(f"PROVENANCE.md: нет строки `{DLC_MODULE}` `{dlc}` с суммой h1 (D-18)")
    if sha is None:
        raise RuntimeError(f"PROVENANCE.md: нет строки `{dbip_rel}` с SHA-256 (§4)")
    return h1, sha


def go(args, env, what):
    r = subprocess.run(["go", *args], cwd=TOOL, env=env, capture_output=True, text=True)
    if r.returncode != 0:
        tail = "\n".join((r.stdout + r.stderr).strip().splitlines()[-40:])
        raise RuntimeError(f"{what}: код {r.returncode}\n{tail}")
    return r.stdout


def main():
    ap = argparse.ArgumentParser(description="Набор геоданных DPpass (D-27)")
    ap.add_argument("--out", default=DEFAULT_OUT, help="каталог; набор — в DIR/geodata/")
    ap.add_argument("--test", action="store_true", help="go vet и go test сборщика; набор целиком — через ядро Xray")
    a = ap.parse_args()
    try:
        if shutil.which("go") is None:
            raise Missing("нет Go (go в PATH) — набор геоданных не собрать")
        try:
            env = goenv.go_env()
        except goenv.UnsafeGoEnv as e:
            raise RuntimeError(str(e))
        dlc, release = pinned()
        source = dbip_file(release)
        h1, sha = recorded_sums(dlc, rel(source))

        if not os.path.isfile(source):
            raise RuntimeError(f"нет {rel(source)} — выпуск DB-IP {release} из каталога (D-31)")
        with open(source, "rb") as f:
            got = hashlib.sha256(f.read()).hexdigest()
        if got != sha:
            raise RuntimeError(f"{rel(source)}: SHA-256 {got}, в PROVENANCE.md — {sha}: файл подменён или запись устарела")

        info = json.loads(go(["mod", "download", "-json", f"{DLC_MODULE}@{dlc}"], env, f"загрузка {DLC_MODULE}@{dlc}"))
        if info.get("Error"):
            raise RuntimeError(f"{DLC_MODULE}@{dlc}: {info['Error']}")
        if info.get("Sum") != h1:
            raise RuntimeError(f"{DLC_MODULE}@{dlc}: сумма архива {info.get('Sum')}, в PROVENANCE.md — {h1}")
        commit = (info.get("Origin") or {}).get("Hash", "")
        if commit and not dlc.endswith("-" + commit[:12]):
            raise RuntimeError(f"{DLC_MODULE}@{dlc}: коммит {commit} не совпадает с псевдоверсией")

        if a.test:
            go(["vet", "./geodata"], env, "go vet сборщика")
            go(["test", "-count=1", "./geodata"], env, "go test сборщика")
        os.makedirs(os.path.dirname(BUILDER), exist_ok=True)
        go(["build", "-trimpath", "-o", BUILDER, "./geodata"], env, "сборка dppass-geodata")

        out = os.path.join(os.path.abspath(a.out), SET_DIR)
        shutil.rmtree(out, ignore_errors=True)
        cmd = [BUILDER, "-dlc", info["Dir"], "-dlc-version", dlc, "-dbip", source, "-dbip-release", release, "-out", out]
        r = subprocess.run(cmd + (["-verify"] if a.test else []), capture_output=True, text=True)
        if r.returncode != 0:
            raise RuntimeError(f"сборка набора: {(r.stdout + r.stderr).strip()}")
        tested = "go vet и go test сборщика; " if a.test else ""
        print(f"{r.stdout.strip()}; {tested}набор — {rel(out) if out.startswith(PROJ) else out}")
        return 0
    except Missing as e:
        print(f"✗ {e}")
        return 3
    except RuntimeError as e:
        print(f"✗ {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
