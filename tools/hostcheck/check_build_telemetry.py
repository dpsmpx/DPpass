#!/usr/bin/env python3
"""Сборка ничего не отправляет и не копит о себе (D-12 для инструментов).

Что сборка делает с сетью, проверено 17 октября 2026: полная пересборка
модулей JVM, `:app` и Lint под `strace -f -e trace=connect,sendto,sendmsg`
открывала соединения только с 127.0.0.1 — процессы Gradle и Kotlin между
собой (`docs/PROCESS.md`, «Перед слиянием»). Эта проверка держит условия,
при которых это так:

  * `gradle.properties`: `org.gradle.welcome=never` (без новостей Gradle
    из сети) и `kotlin.internal.collectFUSMetrics=false` — плагин Kotlin не
    пишет статистику сборки (FUS) в `~/.gradle/kotlin-profile`. Сам он её не
    отправляет, но файлы с путём проекта и версией ОС забирает статистика
    IDE, если её включили. То же свойство — в `build-logic/gradle.properties`:
    у включённой сборки свои свойства;
  * в настройках сборок нет плагинов сканов сборки (Develocity, Gradle
    Enterprise) — скан уходит на чужой сервер;
  * статистика Android Gradle Plugin на этой машине выключена:
    `analytics.settings` в `$ANDROID_USER_HOME` (или `~/.android`) без
    `"hasOptedIn": true`. Включают её в Android Studio, и тогда AGP может
    отправлять статистику и при сборке из командной строки; выключателя
    в проекте у AGP нет. Файла нет — статистика не включалась.

    python3 tools/hostcheck/check_build_telemetry.py

Код возврата: 0 — чисто; 1 — нарушения.
"""
import json
import os
import re
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
# Свойства: {файл: {имя: значение}}.
PROPERTIES = {
    "gradle.properties": {"org.gradle.welcome": "never", "kotlin.internal.collectFUSMetrics": "false"},
    "build-logic/gradle.properties": {"kotlin.internal.collectFUSMetrics": "false"},
}
SETTINGS = ("settings.gradle.kts", "build-logic/settings.gradle.kts")
SCAN_PLUGINS = re.compile(r"com\.gradle\.(develocity|enterprise|build-scan)|gradle-enterprise|develocity", re.I)


def properties(path):
    """{имя: значение} из файла свойств Java (строки `имя=значение`, без продолжений)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith(("#", "!")) or "=" not in line:
                continue
            k, v = line.split("=", 1)
            out[k.strip()] = v.strip()
    return out


def android_settings():
    """Путь к analytics.settings AGP на этой машине (может не существовать)."""
    home = os.environ.get("ANDROID_USER_HOME")
    if not home:
        root = os.environ.get("ANDROID_PREFS_ROOT") or os.environ.get("ANDROID_SDK_HOME") or os.path.expanduser("~")
        home = os.path.join(root, ".android")
    return os.path.join(home, "analytics.settings")


def main():
    problems = []
    for rel, wanted in PROPERTIES.items():
        path = os.path.join(PROJ, rel)
        if not os.path.isfile(path):
            problems.append(f"{rel}: файла нет — нужны {', '.join(f'{k}={v}' for k, v in wanted.items())}")
            continue
        have = properties(path)
        for k, v in wanted.items():
            if have.get(k) != v:
                problems.append(f"{rel}: {k}={have.get(k, '(нет)')} — нужно {k}={v}")
    for rel in SETTINGS:
        path = os.path.join(PROJ, rel)
        if os.path.isfile(path):
            with open(path, encoding="utf-8") as f:
                for n, line in enumerate(f, 1):
                    if SCAN_PLUGINS.search(line) and not line.lstrip().startswith("//"):
                        problems.append(f"{rel}:{n}: плагин сканов сборки — скан уходит на чужой сервер (D-12)")

    agp = android_settings()
    agp_state = "файла нет — статистика не включалась"
    if os.path.isfile(agp):
        try:
            with open(agp, encoding="utf-8") as f:
                opted = json.load(f).get("hasOptedIn")
        except (OSError, ValueError) as e:
            problems.append(f"{agp}: не прочитан ({e}) — включена ли статистика AGP, неизвестно")
        else:
            if opted is True:
                problems.append(
                    f"{agp}: \"hasOptedIn\": true — AGP может отправлять статистику и при сборке из командной строки; "
                    "выключите её в Android Studio (раздел Data Sharing) "
                    "или поставьте \"hasOptedIn\": false"
                )
            agp_state = "выключена"

    if problems:
        print("✗ Сборка может отправлять или копить данные о себе (D-12):")
        for p in problems:
            print("    " + p)
        return 1
    print(f"✓ Телеметрия сборки: свойства Gradle и Kotlin на месте, сканов сборки нет, статистика AGP — {agp_state}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
