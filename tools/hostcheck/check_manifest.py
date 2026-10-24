#!/usr/bin/env python3
"""Манифест и сетевые настройки приложения — по модели безопасности.

Проверяет `app/src/main/AndroidManifest.xml` и связанные XML
(docs/SECURITY_MODEL.md, docs/research/ANDROID_NETWORK_MODEL.md, D-17, D-19):

  * разрешения — ровно утверждённый набор (новое разрешение — правка
    этого списка с причиной, а не случайность из зависимости);
  * оборудование (`uses-feature`) — только утверждённое и необязательное
    (`required="false"`): без камеры приложение ставится и работает (D-71);
  * резервные копии выключены: `allowBackup=false`,
    `fullBackupContent=false`, правила извлечения исключают все домены
    и для облака, и для переноса на другое устройство;
  * открытый HTTP запрещён (`usesCleartextTraffic=false` и
    network_security_config), доверие — только системным CA;
  * нет `debuggable`; экспортировано только то, что нужно: запуск
    Activity (фильтры — только запуск и «Поделиться» текстом и картинкой, D-42, D-65),
    VpnService под `BIND_VPN_SERVICE`, плитка под
    `BIND_QUICK_SETTINGS_TILE` и служба задач под `BIND_JOB_SERVICE`
    (D-39, D-40): каждый сервис — под своим системным разрешением;
  * приёмники (`<receiver>`) — только утверждённые, не экспортированные,
    с утверждёнными событиями; приёмник загрузки выключен по умолчанию и
    включается только с напоминанием о конце подписки (D-76, D-40);
  * видимость пакетов (`<queries>`) — только приложения с ярлыком
    запуска (D-38), без `QUERY_ALL_PACKAGES`;
  * один процесс (D-30): ни у приложения, ни у компонентов нет
    `android:process` — ядро, хранилище и журнал рассчитаны на один
    процесс.

    python3 tools/hostcheck/check_manifest.py

Код возврата: 0 — чисто; 1 — нарушения; 2 — нет манифеста.
"""
import os
import sys
import xml.etree.ElementTree as ET

PROJ = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MAIN = os.path.join(PROJ, "app", "src", "main")
A = "{http://schemas.android.com/apk/res/android}"

# Утверждённые разрешения — с причиной каждого.
PERMISSIONS = {
    "android.permission.INTERNET": "сокеты ядра к серверу и загрузка подписок",
    "android.permission.FOREGROUND_SERVICE": "сервис туннеля работает в foreground",
    "android.permission.FOREGROUND_SERVICE_SPECIAL_USE": "тип foreground-сервиса specialUse (Android 14+)",
    "android.permission.POST_NOTIFICATIONS": "постоянное уведомление, пока туннель поднят (Android 13+)",
    "android.permission.ACCESS_NETWORK_STATE": "сеть под туннелем — setUnderlyingNetworks по сети по умолчанию (D-40)",
    "android.permission.CAMERA": "QR камерой (D-71): запрос при первом нажатии, камера — только пока открыт экран сканирования",
    "android.permission.SCHEDULE_EXACT_ALARM": "будильник о конце подписки в точное время (D-76): с Android 14 его включает пользователь; без него — окно в час",
    "android.permission.RECEIVE_BOOT_COMPLETED": "будильник о конце подписки заново после загрузки (D-76): приёмник включён, только пока напоминание включено",
}
# Приёмники → (события фильтра, выключен ли по умолчанию). Все — не экспортированы:
# события загрузки шлёт система, остальное — свои PendingIntent.
RECEIVERS = {
    ".app.ExpiryReceiver": (frozenset(), False),
    ".app.ExpiryBootReceiver": (frozenset({
        "android.intent.action.BOOT_COMPLETED",
        "android.intent.action.MY_PACKAGE_REPLACED",
        "android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED",
    }), True),
}
# Утверждённое оборудование — всё необязательное (required="false"), с причиной.
FEATURES = {
    "android.hardware.camera.any": "QR камерой (D-71): любая камера, не только задняя",
    "android.hardware.camera": "разрешение CAMERA иначе требовало бы заднюю камеру",
}
BACKUP_DOMAINS = {"root", "file", "database", "sharedpref", "external"}
# Экспортированный компонент → разрешение, которое обязан требовать (None — Activity без разрешения).
EXPORTED_OK = {
    ".app.MainActivity": None,
    ".app.DPpassVpnService": "android.permission.BIND_VPN_SERVICE",
    ".app.DPpassTileService": "android.permission.BIND_QUICK_SETTINGS_TILE",
    ".app.SubscriptionJobService": "android.permission.BIND_JOB_SERVICE",
}
# Фильтры MainActivity: запуск, «Поделиться» текстом (D-42) и картинкой с QR (D-65) — и ничего больше.
MAIN_FILTERS = {
    (("android.intent.action.MAIN",), ("android.intent.category.LAUNCHER",), ()),
    (("android.intent.action.SEND",), ("android.intent.category.DEFAULT",), ("text/plain",)),
    (("android.intent.action.SEND",), ("android.intent.category.DEFAULT",), ("image/*",)),
}


def resource(ref):
    """`@xml/имя` → путь к файлу ресурса."""
    if not ref or not ref.startswith("@xml/"):
        return None
    return os.path.join(MAIN, "res", "xml", ref[len("@xml/"):] + ".xml")


def main():
    manifest = os.path.join(MAIN, "AndroidManifest.xml")
    if not os.path.isfile(manifest):
        print("✗ check_manifest: нет app/src/main/AndroidManifest.xml")
        return 2
    root = ET.parse(manifest).getroot()
    app = root.find("application")
    problems = []

    declared = {p.get(A + "name") for p in root.findall("uses-permission")} | {
        p.get(A + "name") for p in root.findall("uses-permission-sdk-23")}
    for p in sorted(declared - set(PERMISSIONS)):
        problems.append(f"разрешение {p} не утверждено (список и причины — tools/hostcheck/check_manifest.py)")
    for p in sorted(set(PERMISSIONS) - declared):
        problems.append(f"нет разрешения {p}: {PERMISSIONS[p]}")

    for f in root.findall("uses-feature"):
        name = f.get(A + "name")
        if name not in FEATURES:
            problems.append(f"оборудование {name} не утверждено (список и причины — tools/hostcheck/check_manifest.py)")
        elif f.get(A + "required") != "false":
            problems.append(f"оборудование {name} должно быть необязательным (required=\"false\"): {FEATURES[name]}")
    for name in sorted(set(FEATURES) - {f.get(A + "name") for f in root.findall("uses-feature")}):
        problems.append(f"нет <uses-feature {name} required=\"false\">: {FEATURES[name]}")

    def attr(name):
        return app.get(A + name) if app is not None else None

    if app is None:
        problems.append("нет <application>")
    else:
        if attr("allowBackup") != "false":
            problems.append("android:allowBackup должен быть false: подписки и ключи не уезжают в резервную копию (D-19)")
        if attr("fullBackupContent") != "false":
            problems.append("android:fullBackupContent должен быть false (Android ≤ 11)")
        if attr("usesCleartextTraffic") != "false":
            problems.append("android:usesCleartextTraffic должен быть false")
        if attr("process") is not None:
            problems.append("<application android:process>: приложение работает в одном процессе (D-30)")
        if attr("debuggable") is not None:
            problems.append("android:debuggable в манифесте запрещён — его ставит тип сборки")

        rules = resource(attr("dataExtractionRules"))
        if not rules or not os.path.isfile(rules):
            problems.append("нет android:dataExtractionRules (Android 12+)")
        else:
            r = ET.parse(rules).getroot()
            for section in ("cloud-backup", "device-transfer"):
                s = r.find(section)
                excluded = {e.get("domain") for e in s.findall("exclude")} if s is not None else set()
                included = s.findall("include") if s is not None else []
                if included or excluded != BACKUP_DOMAINS:
                    missing = ", ".join(sorted(BACKUP_DOMAINS - excluded)) or "—"
                    problems.append(f"{os.path.relpath(rules, PROJ)}: <{section}> должен исключать все домены (не хватает: {missing}) и ничего не включать")

        nsc = resource(attr("networkSecurityConfig"))
        if not nsc or not os.path.isfile(nsc):
            problems.append("нет android:networkSecurityConfig")
        else:
            n = ET.parse(nsc).getroot()
            rel = os.path.relpath(nsc, PROJ)
            base = n.find("base-config")
            if base is None or base.get("cleartextTrafficPermitted") != "false":
                problems.append(f"{rel}: base-config должен запрещать открытый HTTP")
            for el in n.iter():
                if el.get("cleartextTrafficPermitted") == "true":
                    problems.append(f"{rel}: <{el.tag}> разрешает открытый HTTP")
                if el.tag == "certificates" and el.get("src") not in ("system",):
                    problems.append(f"{rel}: доверие к сертификатам «{el.get('src')}» — только system (подмена TLS через пользовательский CA)")
            if n.find("debug-overrides") is not None:
                problems.append(f"{rel}: debug-overrides запрещены")

        for kind in ("activity", "activity-alias", "service", "receiver", "provider"):
            for el in app.findall(kind):
                name = el.get(A + "name")
                if el.get(A + "process") is not None:
                    problems.append(f"<{kind} {name}> android:process: компоненты — в процессе приложения (D-30)")
                exported = el.get(A + "exported")
                if exported is None and el.find("intent-filter") is not None:
                    problems.append(f"<{kind} {name}>: android:exported не указан явно")
                if exported != "true":
                    continue
                if name not in EXPORTED_OK:
                    problems.append(f"<{kind} {name}> экспортирован без причины (список — tools/hostcheck/check_manifest.py)")
                elif EXPORTED_OK[name] is not None and el.get(A + "permission") != EXPORTED_OK[name]:
                    problems.append(f"<{kind} {name}> должен требовать {EXPORTED_OK[name]}")
                if kind in ("service", "receiver", "provider") and not el.get(A + "permission"):
                    problems.append(f"<{kind} {name}> экспортирован без android:permission")
                if name == ".app.MainActivity":
                    filters = {
                        (
                            tuple(sorted(a.get(A + "name") for a in f.findall("action"))),
                            tuple(sorted(c.get(A + "name") for c in f.findall("category"))),
                            tuple(sorted(d.get(A + "mimeType") for d in f.findall("data") if d.get(A + "mimeType"))),
                        )
                        for f in el.findall("intent-filter")
                    }
                    for extra in sorted(filters - MAIN_FILTERS):
                        problems.append(f"<activity {name}>: фильтр {extra} не утверждён (D-42, D-65: только запуск, SEND text/plain и SEND image/*)")
                    for f in el.findall("intent-filter"):
                        if any(d.get(A + "scheme") or d.get(A + "host") for d in f.findall("data")):
                            problems.append(f"<activity {name}>: фильтр со схемой или хостом — ссылки снаружи не принимаются")
                actions = {a.get(A + "name") for f in el.findall("intent-filter") for a in f.findall("action")}
                if "android.net.VpnService" in actions and el.get(A + "permission") != "android.permission.BIND_VPN_SERVICE":
                    problems.append(f"<{kind} {name}>: VpnService должен требовать BIND_VPN_SERVICE")

    receivers = {el.get(A + "name"): el for el in app.findall("receiver")} if app is not None else {}
    for name, el in receivers.items():
        if name not in RECEIVERS:
            problems.append(f"<receiver {name}> не утверждён (список и причины — tools/hostcheck/check_manifest.py)")
            continue
        actions, off = RECEIVERS[name]
        if el.get(A + "exported") != "false":
            problems.append(f"<receiver {name}> должен быть android:exported=\"false\": события шлёт система или свои PendingIntent")
        got = frozenset(a.get(A + "name") for f in el.findall("intent-filter") for a in f.findall("action"))
        if got != actions:
            problems.append(f"<receiver {name}>: события {sorted(got)} — ожидались {sorted(actions)}")
        if off and el.get(A + "enabled") != "false":
            problems.append(f"<receiver {name}> должен быть выключен по умолчанию (android:enabled=\"false\"): DPpass не запускается при загрузке, пока напоминание выключено (D-40, D-76)")
    for name in sorted(set(RECEIVERS) - set(receivers)):
        problems.append(f"нет <receiver {name}> (D-76)")

    queries = root.find("queries")
    if queries is not None:
        for child in queries:
            ok = child.tag == "intent" and {a.get(A + "name") for a in child.findall("action")} == {"android.intent.action.MAIN"} \
                and {c.get(A + "name") for c in child.findall("category")} == {"android.intent.category.LAUNCHER"}
            if not ok:
                problems.append(f"<queries>: <{child.tag}> — видимость пакетов только по ярлыку запуска (D-38)")

    if problems:
        print("✗ Манифест:")
        for p in problems:
            print("    " + p)
        return 1
    print(f"✓ Манифест: {len(PERMISSIONS)} утверждённых разрешений, оборудование — только необязательное ({len(FEATURES)}), без резервных копий и открытого HTTP, один процесс, экспорт — только {', '.join(EXPORTED_OK)} (сервисы — под системными разрешениями), приёмники — {len(RECEIVERS)} без экспорта, загрузка — выключена по умолчанию, видимость пакетов — только ярлыки запуска")
    return 0


if __name__ == "__main__":
    sys.exit(main())
