#!/usr/bin/env python3
"""Тесты экранов (D-75, D-86): все запускаются и ничего не меняют.

Тесты `app/src/androidTest` идут на настоящих данных приложения на
телефоне автора, они же — на JVM под Robolectric (`app/src/robolectric`,
D-86). Проверяет:

  * запускатель в `app/build.gradle.kts` — `DeviceTestRunner`;
  * каждый набор (`object … : DeviceSuite`) — в `DeviceTests.ALL`: набор
    вне списка не запустился бы никогда, и этого никто бы не заметил;
  * в тестах нет действий, которые меняют данные приложения или телефона:
    нажатий мимо `Device.tap` (он пускает только переходы по экранам),
    настроек, импорта, подключения туннеля, буфера обмена, служб — и в
    тестах телефона, и в запуске на JVM;
  * запуск на JVM берёт все наборы — `DeviceTests.ALL`, а не свой список.

    python3 tools/hostcheck/check_device_tests.py

Код возврата: 0 — чисто; 1 — нарушения.
"""
import os
import re
import sys

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
TESTS = os.path.join(PROJ, "app", "src", "androidTest")
JVM = os.path.join(PROJ, "app", "src", "robolectric")
GRADLE = os.path.join(PROJ, "app", "build.gradle.kts")
RUNNER = "com.dpsmpx.dppass.app.device.DeviceTestRunner"
# Единственное место, где тест нажимает: Device.tap — только вкладки, «Добавить», «Назад».
TAP_HELPER = os.path.join("app", "src", "androidTest", "kotlin", "com", "dpsmpx", "dppass", "app", "device", "Device.kt")

# (выражение, что запрещено, исключения — файлы относительно корня проекта)
FORBIDDEN = [
    (r"\bperformClick\s*\(|\bcallOnClick\s*\(|\bperformLongClick\s*\(", "нажатие мимо Device.tap: тесты нажимают только переходы", {TAP_HELPER}),
    (r"\bAppPrefs\b|\bgetSharedPreferences\s*\(|\.edit\s*\(\s*\)", "настройки приложения", set()),
    (r"\bimportText\s*\(|\bImportFlow\.(handle|fromClipboard)\b", "импорт конфигурации", set()),
    (r"(?<![\w.])(connect|disconnect|reconnectIfBusy)\s*\(|\bDPpassVpnService\b|\bVpnService\b", "подключение туннеля", set()),
    (r"\bClipboardManager\b|\bsetPrimaryClip\s*\(", "буфер обмена телефона", set()),
    (r"\bstart(Foreground)?Service\s*\(|\bsendBroadcast\s*\(", "службы и рассылки", set()),
    (r"\.(activation|subscriptions|userPolicy|share|relays|latency)\b", "состояние ядра: тесты его не трогают", set()),
    (r"\bsetChecked\s*\(|\.isChecked\s*=|\bsetText\s*\(|\.text\s*=", "ввод и переключение", set()),
    (r"\bstartActivity(ForResult)?\s*\(", "запуск экранов мимо Device.launch", set()),
]


def kotlin_files(top):
    for root, _, files in sorted(os.walk(top)):
        for f in sorted(files):
            if f.endswith(".kt"):
                yield os.path.join(root, f)


def strip_comments(text):
    """Без комментариев: запрещённое слово в пояснении — не действие."""
    text = re.sub(r"/\*.*?\*/", lambda m: "\n" * m.group(0).count("\n"), text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def main():
    problems = []
    gradle = open(GRADLE, encoding="utf-8").read() if os.path.isfile(GRADLE) else ""
    if f'testInstrumentationRunner = "{RUNNER}"' not in gradle:
        problems.append(f"app/build.gradle.kts: testInstrumentationRunner — не {RUNNER} (D-75)")

    files = list(kotlin_files(TESTS))
    if not files:
        problems.append("нет тестов app/src/androidTest (D-75)")
    jvm = list(kotlin_files(JVM))
    if not any("DeviceTests.ALL" in strip_comments(open(p, encoding="utf-8").read()) for p in jvm):
        problems.append("app/src/robolectric: запуск на JVM не берёт DeviceTests.ALL — часть наборов не пошла бы (D-86)")
    suites, listed = [], None
    for path in files + jvm:
        rel = os.path.relpath(path, PROJ)
        raw = open(path, encoding="utf-8").read()
        code = strip_comments(raw)
        if path in jvm:
            for n, line in enumerate(code.splitlines(), 1):
                for pattern, what, allowed in FORBIDDEN:
                    if rel not in allowed and re.search(pattern, line):
                        problems.append(f"{rel}:{n}: {what} — тесты экранов только смотрят (D-75, D-86)")
            continue
        suites += [(m.group(1), rel) for m in re.finditer(r"^\s*object\s+(\w+)\s*:\s*DeviceSuite\b", code, re.M)]
        m = re.search(r"val\s+ALL\s*:\s*List<DeviceSuite>\s*=\s*listOf\(([^)]*)\)", code)
        if m:
            listed = {n.strip() for n in m.group(1).split(",") if n.strip()}
        for n, line in enumerate(code.splitlines(), 1):
            for pattern, what, allowed in FORBIDDEN:
                if rel not in allowed and re.search(pattern, line):
                    problems.append(f"{rel}:{n}: {what} — тесты на телефоне только смотрят (D-75)")

    if listed is None:
        problems.append("нет DeviceTests.ALL — списка наборов (D-75)")
    else:
        for name, rel in suites:
            if name not in listed:
                problems.append(f"{rel}: набор {name} не в DeviceTests.ALL — не запустится")
        for name in sorted(listed - {s for s, _ in suites}):
            problems.append(f"DeviceTests.ALL: {name} — не набор DeviceSuite")

    if problems:
        print("✗ Тесты экранов:")
        for p in problems:
            print("    " + p)
        return 1
    print(f"✓ Тесты экранов: наборов {len(suites)}, все в DeviceTests.ALL и на JVM; действий, меняющих данные, нет")
    return 0


if __name__ == "__main__":
    sys.exit(main())
