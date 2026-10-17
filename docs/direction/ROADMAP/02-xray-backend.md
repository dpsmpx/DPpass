# Этап 2 — Реальное ядро (Xray)

Состояние: **выполнен** (17 октября 2026).

## Цель

Заменить фиктивное ядро настоящим — Xray-core (D-03) — за той же
границей `ProxyEngine`/`BackendCompiler` (D-04) и поднять туннель на
устройстве без утечек.

## Вход

- Этап 1 выполнен.
- Версия Xray выбрана по чек-листу D-18 (`docs/PROCESS.md`,
  «Зависимости»); строка в `docs/legal/THIRD_PARTY_MATRIX.md` из
  «запланирован» переведена в «разрешён» вместе с `docs/PROVENANCE.md`.
  Выполнено: Xray 26.9.30 (D-24).

## Работы

1. **Матрица возможностей Xray** выбранной версии — `EngineCapabilities`
   с тестом: что из IR v1 (D-16) Xray выражает, что — нет.
   Сделано: `XrayBackend.CAPABILITIES`, `XrayCompilerTest.matrixLacksOnlyWhatXrayCannotExpress`.
2. **Компилятор IR → JSON Xray** (`engine/`, пакет своего бэкенда):
   протоколы, транспорты, защиты IR v1; маршрутизация (`engineRules`
   после `AppLowering`), DNS, вход TUN. Отказ с путём там, где смысл не
   сохраняется (D-05). Тесты: корпус `tests/data/configs/` компилируется,
   результат сверяется с эталонными файлами (golden) и проверяется
   самим Xray (`-test`) на хосте. Сделано: `XrayCompiler`,
   `XrayCompilerTest`, эталоны `tests/data/xray/`, шаг hostcheck «Xray»
   (`docs/TESTING.md`, «Эталоны Xray»).
3. **Сверка смысла маршрутизации**: на корпусе запросов
   `tests/data/routing/` решение Xray совпадает с `RouteEvaluator`
   (на хосте, через тестовый запуск ядра). Сделано: `*.probe.json` и
   `dppass-xray-probe route` (маршрутизатор Xray без запуска ядра).
4. **Интеграция на Android**: libXray (MIT) или своя обёртка gomobile;
   `ProxyEngine` поверх неё; `protect()` для исходящих сокетов ядра.
   Сделано: своя обёртка Go с JNI (D-25) — мост `tools/xray/bridge` с
   `protect()` и политикой входов, экспорт JNI `tools/xray/jni`,
   `XrayProxyEngine`; библиотека собирается для хоста и трёх ABI Android
   (`tools/xray/native.py`, задача `xrayNative<Вариант>`), тест JNI на
   хосте (`XrayJniTest`), `AppGraph` на Xray. На устройстве не проверено
   (`TODO.md`).
5. **Мост fd → ядро**: вход TUN Xray, без локальных входов (D-30;
   hev-socks5-tunnel отклонён — ему нужен вход SOCKS ядра, T11).
   Стабильность, память, батарея и утечки выбранного пути — замеры на
   устройстве (этап 3); не выдержит — новое решение с замерами.
6. **Сервис туннеля** в процессе приложения (D-30): путь
   `AndroidTunnelProvider.establish` → `TunInput` → `DPpassCore.connect`
   включается. Сделано: `DPpassVpnService` подключает ядро, проверка
   здоровья — запрос DNS через сервер профиля к DNS-серверу конфигурации
   (D-32); на устройстве не проверено (`TODO.md`). Имя сервера резолвит система вне туннеля (D-29).
   Геоданные на устройстве — свой набор в APK (D-27): сборка набора,
   перенос в `noBackupFilesDir/geodata`, сверка кодов компилятором.
   Сделано для геоданных: сборщик `tools/xray/geodata` (D-31), набор в
   APK (`xrayGeodata<Вариант>`, `check_apk.py`), перенос в `AppGraph`
   (`GeodataInstaller`), сверка кодов, атрибутов и их сочетаний
   (`GEO_CODE_UNKNOWN`), объяснение решений на наборе ядра
   (`XrayGeoResolver` → `bridge.GeoMatch`); на устройстве не проверено
   (`TODO.md`).
7. **Проверки**: выравнивание нативных библиотек по 16 КБ — шаг
   hostcheck; размер APK по ABI — в `docs/PERFORMANCE_BUDGET.md`.
   Сделано: `check_apk.py` (только библиотека ядра трёх ABI, без
   сжатия, выравнивание в zip и ELF по 16 КБ), размер APK одного ABI —
   предел в бюджете (D-28).

## Критерии выхода

- [x] VLESS + REALITY + Vision и ещё по одному кандидату классов HTTP/CDN и
      UDP/QUIC подключаются на устройстве через TUN (Redmi 13, Android 15:
      HTTP/CDN — 6 октября 2026, TCP_STREAM и Hysteria2 — 17 октября 2026;
      `TODO.md`, «На устройстве»).
- [x] Нет утечек: IPv6 и DNS приложений в туннеле не идут мимо него
      (проверка на устройстве 17 октября 2026 — запись в `TODO.md`).
- [x] Компиляция корпуса и сверка маршрутизации — в hostcheck (шаг «Xray», D-24).
- [x] `MockProxyEngine` остаётся вторым бэкендом в тестах; в приложении его
      больше нет (`check_modules.py`: правило `engine.mock`).

## Не делается

Второе реальное ядро; интерфейс продукта; загрузка подписок по сети.
