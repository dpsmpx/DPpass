#!/usr/bin/env python3
"""Архивы для сборки Windows (D-97): JDK Temurin и Wintun — скачать и сверить.

    python3 tools/desktop/windows_deps.py [temurin|wintun ...]

Версии — из каталога (`gradle/libs.versions.toml`: `temurin-windows`,
`wintun`), SHA-256 — из `docs/PROVENANCE.md`, раздел «Windows». Архив
скачивается один раз в `build/windows/downloads/` и сверяется при каждом
обращении: сумма не совпала — файл удаляется и сборка останавливается
(T10), а не идёт с подменённым архивом. В репозиторий архивы не кладутся.

Без имён — оба архива. Вызывают `tools/xray/native.py windows` (заголовки
JNI из JDK) и сборка комплекта (jmods, `wintun.dll`).

Код возврата: 0 — архивы на месте и сверены; 1 — ошибка; 3 — нет сети.
"""
import hashlib
import os
import re
import sys
import tomllib
import urllib.error
import urllib.request
import zipfile

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CATALOG = os.path.join(PROJ, "gradle", "libs.versions.toml")
PROVENANCE = os.path.join(PROJ, "docs", "PROVENANCE.md")
OUT = os.path.join(PROJ, "build", "windows")
DOWNLOADS = os.path.join(OUT, "downloads")


class Missing(Exception):
    """Архив не скачать: нет сети."""


def versions():
    with open(CATALOG, "rb") as f:
        v = tomllib.load(f).get("versions", {})
    temurin, wintun = v.get("temurin-windows"), v.get("wintun")
    if not temurin or not wintun:
        raise RuntimeError("libs.versions.toml: нет версий temurin-windows и wintun (D-97)")
    return {"temurin": temurin, "wintun": wintun}


def archive(name, version):
    """(имя файла, адрес) архива закреплённой версии."""
    if name == "temurin":
        m = re.fullmatch(r"(21\.\d+\.\d+)\+(\d+)", version)
        if not m:
            raise RuntimeError(f"temurin-windows {version!r}: ожидалась версия JDK 21 вида 21.0.N+M")
        file = f"OpenJDK21U-jdk_x64_windows_hotspot_{m[1]}_{m[2]}.zip"
        return file, f"https://github.com/adoptium/temurin21-binaries/releases/download/jdk-{m[1]}%2B{m[2]}/{file}"
    if name == "wintun":
        if not re.fullmatch(r"\d+\.\d+(\.\d+)?", version):
            raise RuntimeError(f"wintun {version!r}: ожидалась версия вида 0.14.1")
        file = f"wintun-{version}.zip"
        return file, f"https://www.wintun.net/builds/{file}"
    raise RuntimeError(f"неизвестный архив {name}")


def recorded_sha(file):
    """SHA-256 архива из PROVENANCE.md, раздел «Windows»: строка с именем файла."""
    with open(PROVENANCE, encoding="utf-8") as f:
        rows = [line for line in f.read().splitlines() if line.lstrip().startswith("|") and f"`{file}`" in line]
    shas = {m for r in rows for m in re.findall(r"`([0-9a-f]{64})`", r)}
    if len(shas) != 1:
        raise RuntimeError(f"PROVENANCE.md: нет строки `{file}` с одной суммой SHA-256 (D-18, D-97)")
    return shas.pop()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def fetch(name):
    """Путь к сверенному архиву name (temurin, wintun)."""
    file, url = archive(name, versions()[name])
    want = recorded_sha(file)
    path = os.path.join(DOWNLOADS, file)
    if not os.path.isfile(path):
        os.makedirs(DOWNLOADS, exist_ok=True)
        part = path + ".part"
        try:
            with urllib.request.urlopen(url, timeout=120) as r, open(part, "wb") as out:
                while chunk := r.read(1 << 20):
                    out.write(chunk)
        except (urllib.error.URLError, OSError) as e:
            if os.path.exists(part):
                os.remove(part)
            raise Missing(f"{file}: не скачать с {url} — {e}")
        os.replace(part, path)
    got = sha256(path)
    if got != want:
        os.remove(path)
        raise RuntimeError(f"{file}: SHA-256 {got}, в PROVENANCE.md — {want}: архив подменён или запись устарела; файл удалён")
    return path


def extract(name, prefix, dest):
    """Распаковать из сверенного архива name файлы под prefix (без корневого каталога) в dest.
    Пути с «..» и абсолютные — отказ: архив извне (T10)."""
    path = fetch(name)
    os.makedirs(dest, exist_ok=True)
    with zipfile.ZipFile(path) as z:
        for info in z.infolist():
            parts = info.filename.split("/", 1)
            if len(parts) < 2 or not parts[1].startswith(prefix) or info.is_dir():
                continue
            rel = parts[1]
            if rel.startswith("/") or ".." in rel.split("/"):
                raise RuntimeError(f"{os.path.basename(path)}: путь {info.filename!r} вне архива")
            target = os.path.join(dest, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with z.open(info) as src, open(target, "wb") as out:
                out.write(src.read())
    return dest


def jni_include():
    """Каталоги заголовков JNI для Windows: include и include/win32 закреплённого Temurin."""
    dest = os.path.join(OUT, f"temurin-{versions()['temurin']}")
    inc = os.path.join(dest, "include")
    if not os.path.isfile(os.path.join(inc, "win32", "jni_md.h")):
        extract("temurin", "include/", dest)
    if not os.path.isfile(os.path.join(inc, "jni.h")):
        raise RuntimeError("в JDK Temurin нет include/jni.h")
    return [inc, os.path.join(inc, "win32")]


def main(argv):
    names = argv or ["temurin", "wintun"]
    try:
        for name in names:
            path = fetch(name)
            print(f"✓ {os.path.relpath(path, PROJ)}: SHA-256 сверена с PROVENANCE.md")
    except Missing as e:
        print(f"✗ {e}")
        return 3
    except RuntimeError as e:
        print(f"✗ {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
