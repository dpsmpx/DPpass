#!/usr/bin/env python3
"""Не выдавать подписанный тестовый APK, который Android отвергнет как downgrade.

Сверяем versionCode исходников с последним публичным Android alpha-релизом.
В GitHub Actions gh использует предоставленный токен только для чтения API.
"""
import base64
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
GRADLE = "app/build.gradle.kts"
TAG = re.compile(r"^v\d+\.\d+\.\d+(?:-(?:alpha|rc)\.\d+)?$")
ALPINE_TAG = re.compile(r"^zapret2-alpine-[0-9a-f]{12}$")


def update_candidate(rel):
    if rel["draft"]:
        return False
    tag = rel["tag_name"]
    if TAG.fullmatch(tag):
        return True
    return bool(ALPINE_TAG.fullmatch(tag) and any(
        a["name"].endswith("-release-signed.apk") for a in rel.get("assets", [])))


def version_code(source: str) -> int:
    match = re.search(r"^\s*versionCode\s*=\s*(\d+)\s*$", source, re.M)
    if not match:
        raise ValueError("Не найден буквальный versionCode в app/build.gradle.kts")
    return int(match.group(1))


def api(path: str):
    output = subprocess.check_output(["gh", "api", path], text=True)
    return json.loads(output)


def latest_published_alpha(repo: str):
    releases = api(f"repos/{repo}/releases?per_page=100")
    published = [r for r in releases if update_candidate(r)]
    if not published:
        raise ValueError("Нет опубликованных Android alpha-релизов для сверки versionCode")
    # Сверяем несколько последних, а не только последний по времени.
    versions = []
    for rel in published:
        tag = rel["tag_name"]
        entry = api(f"repos/{repo}/contents/{GRADLE}?ref={tag}")
        source = base64.b64decode(entry["content"]).decode("utf-8")
        versions.append((version_code(source), tag))
    return max(versions)


def main():
    repo = os.environ.get("GITHUB_REPOSITORY", "dpsmpx/DPpass")
    local = version_code((ROOT / GRADLE).read_text(encoding="utf-8"))
    previous, tag = latest_published_alpha(repo)
    if previous < 154:
        previous, tag = 154, "confirmed installed DPpass 0.8.1"
    if local == previous and os.environ.get("DPPASS_ALLOW_EQUAL_UPGRADE") == "true":
        print(f"✓ versionCode={local}: CI-only build, no publication")
        return 0
    if local <= previous:
        print(f"✗ versionCode={local}: опубликованный {tag} имеет {previous}; "
              "Android отклонит обновление как downgrade. Увеличьте versionCode.")
        return 1
    print(f"✓ versionCode={local} > публичного {tag} ({previous}): обновление допустимо")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, KeyError, subprocess.CalledProcessError) as e:
        print(f"✗ проверка версии: {e}")
        sys.exit(1)
