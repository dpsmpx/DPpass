# Процесс DPpass

Как в DPpass делается изменение, чем оно проверяется и как
обновляются зависимости. Короткая версия правил — `CLAUDE.md`.

## 1. Порядок изменения

1. **Решение раньше кода.** Найти решение, которое изменение
   затрагивает (`docs/direction/DECISIONS.md`), и раздел
   `docs/ARCHITECTURE.md` про модуль. Изменение, которое противоречит
   решению, начинается с нового решения D-NN (следующий свободный номер
   — в шапке журнала), а не с кода.
2. **Задача в рамках этапа.** Этап меняет только то, что в нём
   записано (`docs/direction/ROADMAP/README.md`); найденное «заодно» —
   строка в `TODO.md`, а не правка.
3. **Код, тест и документ — вместе.** Новый модуль — таблица §2 в
   `docs/ARCHITECTURE.md`; новое поле формата — `docs/CONFIG_FORMAT.md` и
   новая версия формата; новая угроза — `docs/SECURITY_MODEL.md`; новый
   предел — `docs/PERFORMANCE_BUDGET.md`; новая зависимость — §3 ниже.
   Сменилось состояние этапа, критерий выхода, решение или пункт
   `TODO.md` — `python3 tools/hostcheck/readme_progress.py` обновляет
   раздел «Прогресс» в `README.md` (руками его не правят).
4. **Новый баг — новый файл корпуса** `tests/data/` (`docs/TESTING.md`,
   «Корпус регрессий»); новый код диагностики — строка в
   `tools/hostcheck/diag_codes.txt` (D-22).
5. **hostcheck зелёный** (§2) — только тогда изменение готово.
6. **PR** — в `main`; описание: что сделано, что осталось, что найдено
   и записано в `TODO.md`; итог полного прогона hostcheck (§5).

## 2. Проверки

### Запуск

Проверки идут через DP Verify (D-50): копия — `tools/dpv/` (руками не
правится; правка — в репозитории DP-Verify и новой поставкой), профиль —
`tools/dpverify.toml`. `tools/hostcheck/run.sh` — обёртка с прежними
ключами.

```sh
tools/hostcheck/run.sh            # dpv run full — всё, что можно на этой машине; пропуск — громко, но не ошибка
tools/hostcheck/run.sh --quick    # dpv run static — быстрые проверки (без Gradle), секунды
tools/hostcheck/run.sh --full     # dpv run full --ci — перед слиянием (§5): закоммиченное дерево, пропуск — ошибка
tools/dpv/dpv run affected        # после задачи: статика и шаги, выбранные по изменениям
tools/dpv/dpv plan affected       # что будет запущено и почему, без запуска
tools/dpv/dpv report --md         # итог последнего прогона — в описание PR
tools/dpv/dpv explain ID          # что ловит проверка, как чинить, как оформить исключение
tools/dpv/dpv doctor              # окружение: Python, git, JDK, Go, Android SDK и NDK
```

Код возврата: 0 — пройдено (в обычном режиме — кроме названных
пропусков); 1 — есть ✗; 2 — неверный вызов или профиль; 3 — сбой DP
Verify. Журнал каждой проверки — `build/dpv/last/<проверка>.log`; отчёт —
`build/dpv/last/report.json` и `report.md`; на экран — итог и находки.
Итог `tools/hostcheck/run.sh --full` ещё и копируется в `build/dpv/full`:
`run.sh report` берёт его, а не последний прогон (D-52).

### Проверки

Встроенные проверки DP Verify (`tools/dpv/dpv explain ID`):

| Проверка | Что ловит | Решения |
|---|---|---|
| `dpv.integrity`, `dpv.profile` | копия `tools/dpv/` разошлась с манифестом; ошибка профиля, исключение без причины или просроченное | D-50 |
| `repo.layout` | лишнее в корне, нет обязательных документов, файлы ключей `*.pem` и workflow CI, большие файлы (кроме выпуска DB-IP) | D-23, D-31, D-35 |
| `format.text` | не UTF-8, BOM, CRLF (кроме `*.bat`), нет перевода строки в конце, хвостовые пробелы, маркеры конфликта; корпус не проверяется | — |
| `format.scripts` | синтаксис скриптов bash и Python | — |
| `security.secrets` | файлы ключей, закрытые ключи, токены; значение не печатается | D-11, D-20 |
| `docs.links` | пути `docs/…` и `tools/…`, имена документов, ссылки Markdown и якоря — на несуществующее | все |
| `docs.refs` | решения D-NN, разделы и §, угрозы T-N, этапы плана, классы тестов — неопределённые | все |
| `process.files` | файлы процесса, журнал решений (номера, поле «Проверка»), `TODO.md` | — |
| `provenance.binaries` | двоичный файл без записи в PROVENANCE или с другим SHA-256 (и `gradle-wrapper.jar`) | D-12, D-18, D-20 |
| `code.forbidden` | DNS мимо туннеля, `reveal()` вне разрешённых мест, стек исключения, печать вне `cli/`, системное время, слабая случайность и криптография, свои `TrustManager`, `android.util.Log`, сон и `runBlocking`, нативный код вне моста; `android.*` вне `app/`, модель сети и фиктивное ядро не на своих местах; координаты и репозитории мимо каталога; «/*» внутри комментария (в Kotlin — вложенный комментарий) | D-02, D-03, D-11, D-18, D-21, D-22, D-25 |
| `data.synthetic` | ссылки прокси на настоящие адреса, несинтетические UUID, IP и домены корпуса — и в открытом виде, и внутри base64 | D-05, D-11, D-20 |
| `provenance.deps` | библиотека или плагин каталога, Gradle из wrapper без строки с той же версией в матрице лицензий и PROVENANCE; SHA-256 дистрибутива Gradle | D-18, D-20 |
| `smoke.cli` | весь конвейер через оболочку JVM: 15 сценариев, коды выхода, вывод, секреты не печатаются | D-11, D-21 |

Предметные шаги DPpass — команды профиля:

| Команда | Что ловит | Решения |
|---|---|---|
| `project.modules` — `tools/hostcheck/check_modules.py` | модули и направления зависимостей не по таблице `docs/ARCHITECTURE.md`, §2 | D-02, D-03 |
| `project.fixtures` — `tools/hostcheck/check_fixtures.py` | непарные файлы корпуса, нестрогие ожидания, несуществующие коды и условия сети, реестр кодов | D-05, D-22 |
| `project.docs` — `tools/hostcheck/check_docs.py` | ссылка `ИмяTest.метод` на несуществующий метод теста | — |
| `project.deps` — `tools/provenance/check_dependencies.py` | модуль Go ядра (`tools/xray/go.mod`) без строки или с другой суммой `go.sum`, Xray не той версии, что в каталоге, `replace`; toolchain Go; проверка сумм артефактов Gradle выключена или неполна (`gradle/verification-metadata.xml`); `kotlin("test")`; источники геоданных | D-18, D-24, D-27, D-31; T10 |
| `project.manifest` — `tools/hostcheck/check_manifest.py` | неутверждённые разрешения, резервные копии, открытый HTTP, лишний экспорт компонентов, экспортированный сервис без своего разрешения, фильтры Activity сверх запуска и «Поделиться» текстом, схемы и адреса в фильтрах, видимость пакетов сверх приложений с ярлыком | D-17, D-19, D-40, D-42 |
| `project.contrast` — `tools/hostcheck/check_contrast.py` | цветовые токены светлой и тёмной темы: разный набор имён; пара «цвет на фоне» из списка скрипта ниже порога WCAG 2.2 AA — текст 4,5:1, граница и состояние элемента управления 3:1; полупрозрачный цвет в паре | D-34 |
| `project.format` — `tools/hostcheck/check_format.py` | невидимые и двунаправленные символы (Trojan Source), табуляции в отступе, одиночный CR | — |
| `project.telemetry` — `tools/hostcheck/check_build_telemetry.py` | сборка может отправлять или копить данные о себе: нет `org.gradle.welcome=never` или `kotlin.internal.collectFUSMetrics=false` (и в `build-logic`), плагин сканов сборки, статистика AGP включена на этой машине (`analytics.settings`) | D-12 |
| `project.readme` — `tools/hostcheck/readme_progress.py --check` | раздел «Прогресс» в `README.md` отстал от плана, критериев выхода, решений, `TODO.md`, аудитов; противоречия между ними (этап «выполнен» при открытых критериях, разное состояние в плане и в файле этапа) | — |
| `project.build` — `tools/hostcheck/steps.sh build` (`./gradlew build :cli:installDist :build-logic:test ktlintCheck`, с Android SDK — `-x :app:build`: APK собирается шагом Android) | ошибки и **предупреждения** компилятора (они — ошибки), модульные и межмодульные тесты, тесты `build-logic` (личность пакета, D-47, D-49), корпус, fuzz; стиль Kotlin по `.editorconfig` — `ktlintCheck`, исправление — `./gradlew ktlintFormat` (D-63) | D-05 … D-22, D-63 |
| `project.xray` — `tools/xray/check_xray.py` | эталон компилятора, который Xray закреплённой версии не принимает (`xray run -test`); решение маршрутизации Xray, не совпавшее с `RouteEvaluator`; собранное ядро не той версии, что в каталоге (`docs/TESTING.md`, «Эталоны Xray») | D-05, D-09, D-24 |
| `project.xray-bridge` — `tools/hostcheck/steps.sh xray-bridge` (`tools/xray/native.py host` и `:tests:integration:xrayJniTest`) | `go vet` и `go test` моста ядра в обеих сборках (с тестовым входом и без); библиотека для JVM хоста, экспорт JNI которой не совпал с `external` объекта `XrayJni`; нарушение договора JNI в JVM хоста — версия, проверка, один экземпляр, защитник сокетов, счётчики (`docs/TESTING.md`, «Мост Xray и JNI») | D-25 |
| `project.geodata` — `tools/xray/geodata.py --test` | `go vet` и `go test` сборщика набора геоданных; источник, чья сумма не совпала с PROVENANCE (DB-IP — файл в репозитории, dlc — Go-модуль со сверкой sum.golang.org); строка источника, которую сборщик не понял; код собранного набора, который ядро Xray не загрузило (`docs/TESTING.md`, «Набор геоданных»); нет кодов, которые компилятор подставляет сам | D-27, D-31, D-38 |
| `project.android` — `:app:build :app:lint` (нужны Go и NDK) | сборка APK вместе с `libdppassxray.so` трёх ABI (задачи `xrayNative<Вариант>` → `tools/xray/native.py android`) и набором геоданных (задачи `xrayGeodata<Вариант>` → `tools/xray/geodata.py`); Lint с `warningsAsErrors`, и для модулей ядра (`checkDependencies`); предупреждения Kotlin в `app/` — ошибки, как у модулей ядра (`allWarningsAsErrors`, с 18.10.2026) | D-17, D-25 |
| `project.android-screens` — `steps.sh android-screens`: библиотека моста для хоста, затем `:app:testDebugUnitTest` с `-Pdppass.robolectric` и `-Pdppass.xray.lib` | тесты экранов телефона (D-75) на JVM под Robolectric, по-русски и по-английски: вкладки, подписи для TalkBack, зоны нажатия от 48 dp, заголовки, состояния переключателей, лист «Добавить» и «Назад», протяжка вниз, `FLAG_SECURE`; ключевые пути с настоящим ядром Xray (D-90): импорт, подключение и отказ, отказ в согласии на VPN, карточка подписки; Robolectric, образ Android и AndroidX — только в этом шаге (свойства), не в обычной сборке и не в APK | D-75, D-86, D-90 |
| `project.android-api` — `tools/hostcheck/check_android_api.py` | вызовы Java API в модулях ядра, которых нет на Android 8.0 (Lint их в JVM-модулях не видит) | D-02, D-17 |
| `project.apk` — `tools/hostcheck/check_apk.py` | в собранном APK: разрешения и компоненты из зависимостей в итоговом манифесте, код не из утверждённых корней пакетов (SDK телеметрии и прочее чужое); нативный код — не ровно `libdppassxray.so` трёх ABI (`arm64-v8a`, `armeabi-v7a`, `x86_64`), сжатая библиотека, смещение в zip или сегменты ELF не выровнены по 16 КБ, нет экспорта JNI; набор геоданных не по своему оглавлению (файлы, SHA-256, сжатие, атрибуция DB-IP), не из источников каталога или не тот, что собрал шаг «Xray: геоданные»; APK одного ABI больше предела (`docs/PERFORMANCE_BUDGET.md`, §4); тексты лицензий (`assets/notices/NOTICES.txt`, задача `legalNotices<Вариант>` → `tools/legal/notices.py`) без компонента из матрицы лицензий или без среды выполнения Go | D-12, D-17, D-20, D-25, D-27, D-28, D-43 |
| `project.apk-release` — `tools/hostcheck/check_apk.py --release` | release, собранный `:app:build` через R8 (D-91), без подписи: в каждом dex — метка R8 режима release; свои классы с файлами и строками исходников (не переименованы — запись о падении читается без карты); native-методы `XrayJni` — ровно `external` исходников; `SocketProtector.protect (I)Z` и его реализация на месте (мост ищет их по имени); каждый компонент манифеста — класс в dex; сборка не отладочная; остальное — как у `project.apk` | D-25, D-26, D-91 |

Проверки уровня `static` (встроенные, кроме `smoke.cli`, и первые семь
команд) работают без сборки и без сети — их стоит запускать перед каждым
коммитом (`--quick`).

### Окружение

| Что | Версия | Зачем |
|---|---|---|
| JDK | 21 | инструменты сборки (`jvmToolchain(21)`); байт-код — Java 17 |
| Python | 3.11 или новее | скрипты `tools/` (`tomllib`) |
| Go | 1.21 или новее (нужную версию toolchain — `go1.27.1` — он скачивает сам по `tools/xray/go.mod`) | шаги «Xray», «Xray: мост и JNI» и «Xray: геоданные»: сборка ядра, `dppass-xray-probe`, библиотеки `libdppassxray` и набора геоданных; без Go шаги пропускаются, а `--full` падает |
| Компилятор C и заголовки JNI | `cc` (gcc или clang) для cgo; `jni.h` из JDK (`JAVA_HOME/include`) | библиотека моста для JVM хоста (`native.py host`) |
| Android SDK | платформа 36 (`compileSdk`) и build-tools (`aapt2`, `dexdump`), путь — `ANDROID_HOME` или `sdk.dir` в `local.properties` | модуль `app`, `check_android_api.py`, `check_apk.py`; без SDK `app` не подключается, а `--full` падает |
| Android NDK | версия из `gradle/libs.versions.toml` (`android-ndk`, сейчас `30.0.16248370`) в `$ANDROID_HOME/ndk/<версия>`; ставится `sdkmanager "ndk;30.0.16248370"` | сборка `libdppassxray.so` для APK (D-25); без NDK (или без Go) шаги Android пропускаются, а `--full` падает |
| Сеть | при первом запуске | Gradle скачивает дистрибутив (сверяя SHA-256) и зависимости из Maven Central и Google Maven; Go — toolchain и модули с proxy.golang.org (сверяя с `go.sum` и sum.golang.org) |

В веб-сессии Claude Code окружение готовит хук начала сессии
`.claude/hooks/session-start.sh` (D-50): ставит command-line tools
Android SDK (архив сверяется по SHA-256), платформу, build-tools,
platform-tools и NDK версии из каталога, записывает путь к SDK в
`ANDROID_HOME` сессии и в `local.properties`, направляет Gradle к
Maven Central через его зеркало у Google (только сборку DPpass; суммы
сверяет `gradle/verification-metadata.xml`, D-50), вызывает
`tools/dpv/dpv doctor` и показывает ветки с невлитой работой.

### Правила

- **Падающая проверка не ослабляется.** Тест и проверку чинят или
  меняют вместе с решением; отключить, пропустить, поднять порог «чтобы
  прошло» нельзя (`CLAUDE.md`, «Чего не делать»).
- **Исключение — с причиной и в одном месте:** `[[waiver]]` в
  `tools/dpverify.toml` (причина и срок или пункт `TODO.md`; без них —
  находка `dpv.profile`), разрешённые места правил профиля (`allow`),
  `tools/hostcheck/android_api_allow.txt`. Исключение без причины —
  ошибка обзора.
- **Пропуск — громкий.** Шаг, который нельзя выполнить на этой машине,
  называется в итоге как пропущенный; в `--full` пропуск —
  ошибка.
- **Новая проверка доказывает себя:** до включения в профиль она
  должна поймать намеренно внесённое нарушение и пройти на чистом коде.

## 3. Зависимости

Чек-лист D-18 — для новой библиотеки, плагина, новой версии, Gradle,
а с этапа 2 — и ядра прокси. Обновление делается не
«потому что вышло», а по причине: исправление уязвимости, нужная
возможность, требование платформы.

1. **Причина** — в описании изменения.
2. **Журнал изменений** между версиями прочитан: ломающие изменения,
   изменения поведения по умолчанию, новые сетевые обращения и сбор
   данных (D-12).
3. **Лицензия** по POM (или `LICENSE` на закреплённом коммите) той
   версии, что берётся; смена лицензии — остановка и пересмотр строки
   матрицы, а не обновление молча.
4. **Каталог** — версия только в `gradle/libs.versions.toml`;
   координат и версий плагинов мимо каталога нет.
5. **Записи** в том же изменении: строка в `docs/legal/THIRD_PARTY_MATRIX.md`
   (лицензия, куда попадает, статус) и в `docs/PROVENANCE.md` (откуда,
   как проверено, дата).
6. **Gradle**: `./gradlew wrapper --gradle-version X --distribution-type bin
   --gradle-distribution-sha256-sum <сумма>`, где сумма — из
   `services.gradle.org/distributions/gradle-X-bin.zip.sha256`; SHA-256
   нового `gradle-wrapper.jar` сверяется с `gradle-X-wrapper.jar.sha256`;
   обе суммы — в `docs/PROVENANCE.md`, §3.
7. **Ядро прокси** (D-24): новая версия — в каталоге (`xray`,
   `xray-go-module`) и в `tools/xray/go.mod` (`go get` версии upstream,
   затем `go mod tidy`; `go.sum` — только так, не руками); каждый
   модуль `go.mod` — строка матрицы (лицензия — по файлу в архиве
   модуля) и PROVENANCE (версия и сумма `h1:` из `go.sum`);
   `capabilityDiff` старой и новой матрицы возможностей — в описании
   изменения; эталоны перезаписаны (`docs/TESTING.md`, «Эталоны Xray»)
   и их разница просмотрена; шаг «Xray» зелёный.
8. **Суммы артефактов** (T10): `tools/provenance/update_verification.sh`
   с Android SDK пересоздаёт `gradle/verification-metadata.xml` — SHA-256
   каждого артефакта, который берёт сборка (задачи полного прогона и
   release по ABI). Метаданные модулей скрипт читает заново
   (`--refresh-dependencies`), как машина с пустым кэшем Gradle: при тёплом
   кэше Gradle не перечитывает `.pom` модулей с `.module`, и их суммы
   пропали бы, а сборка на новой машине упала бы на проверке (18 октября
   2026). Разница файла просматривается: новые суммы — только у
   новых версий, у старых ничего не меняется. Сборка с подменённым
   артефактом той же версии падает на проверке Gradle;
   `check_dependencies.py` следит, что проверка включена и у каждой
   библиотеки каталога есть суммы.
9. **Полный прогон**: `tools/hostcheck/run.sh --full` зелёный,
   корпус и fuzz — без новых находок.

## 4. Тестовые сборки

Сборки для устройств автора (D-35) — не выпуск (выпуск — этап 5):
`release` без R8, версия с `-dev`, подпись ключом разработчика.

1. Ключ — только из окружения: `DPPASS_SIGNING_KEYSTORE_BASE64` (или
   путь `DPPASS_SIGNING_KEYSTORE`), `DPPASS_SIGNING_STORE_PASSWORD`,
   `DPPASS_SIGNING_KEY_ALIAS`, `DPPASS_SIGNING_KEY_PASSWORD`. В облачной
   сессии — секреты окружения, которые задаёт автор.
2. `python3 tools/release/sign_apks.py` собирает APK на каждый ABI
   (`-Pdppass.abiSplit=true`, D-28), подписывает `apksigner` (пароли —
   по имени переменной, не в командной строке), сверяет сертификат с
   отпечатком из `docs/PROVENANCE.md`, §7, проверяет каждый APK
   `check_apk.py --abi` и пишет `SHA256SUMS` и `CERTIFICATE.txt`. Без
   ключа или без записанного отпечатка — отказ, отладочный ключ не
   подставляется. Имя пакета и ярлык — случайные на вид, но постоянные
   для ключа (D-49): зерно выводится из отпечатка и пароля, у всех APK
   один пакет, он записан в `CERTIFICATE.txt`.
3. Если файла ключа в сессии нет, а пароль хранилища есть,
   `sign_apks.py --unsigned` собирает те же APK без подписи: личность —
   из отпечатка, записанного в `docs/PROVENANCE.md`, §7, и пароля
   (`DPPASS_SIGNING_STORE_PASSWORD`), выравнивание и `check_apk.py --abi`
   — как обычно. Подписывает автор на своём устройстве в Termux
   скриптом `tools/release/dppass-sign-termux.sh`, который кладётся
   рядом с APK: он сверяет APK с `SHA256SUMS`, пароль — с зерном сборки
   (`seed-sha256` в `CERTIFICATE.txt`; другой пароль дал бы другой
   пакет, D-49), подписывает ключом `~/dppass-keys/dppass-dev.p12`, не
   трогая выравнивание, и сверяет сертификат с отпечатком.
4. APK кладутся в ветку `apk` без истории `main` (двоичных файлов в
   `main` нет, `docs/PROVENANCE.md`, §4): APK, `SHA256SUMS`,
   `CERTIFICATE.txt` и `README.md` с коммитом `main`, из которого собраны;
   у сборки без подписи — и скрипт подписи. В `main` ветка `apk` не
   вливается.

## 5. Перед слиянием

CI нет: GitHub Actions в DPpass не используется и не запускается
(D-23), workflow в `.github/workflows/` не добавляются — `repo.layout`
считает их ошибкой. Ничего не ждёт «зелёного CI».

Условие слияния в `main`:

1. `tools/hostcheck/run.sh --full` (то есть `tools/dpv/dpv run full
   --ci`) выполнен **локально** на последнем коммите PR, на машине с
   JDK 21, Python 3.11+, Go, Android SDK и NDK (§2, «Окружение»), и
   прошёл.
2. Итог прогона — `tools/dpv/dpv report --md` — в описании PR: в нём
   коммит, на котором он сделан.
3. Если Android SDK нет, прогон частичный и так и называется; слияние —
   после полного прогона, а не вместо него.
4. Исключение — правка только Linux-оболочки (`dppass/desktop/`,
   `dppass/tools/desktop/`, документы): `--full` не нужен. Нужны
   `:ktlintCheck`, `:desktop:test`, `tools/desktop/netns_check.py` от
   root и `--quick` (`DPmetaApp:D-32`).

Правила, которые остаются в силе без CI:

- **Gradle тот же у всех:** через wrapper с проверкой SHA-256
  дистрибутива; `gradle-wrapper.jar` сверяет с PROVENANCE
  `provenance.binaries`.
- **Сборка ничего не отправляет:** без сканов сборки и сервисов
  аналитики (D-12; `org.gradle.welcome=never` и
  `kotlin.internal.collectFUSMetrics=false` в `gradle.properties`, условия
  держит `project.telemetry`). Проверено 17 октября 2026: полная
  пересборка модулей JVM, `:app` и Lint (112 задач, `--no-daemon
  --offline --rerun-tasks`) под
  `strace -f -e trace=connect,sendto,sendmsg` соединялась только с
  127.0.0.1 — процессы Gradle и Kotlin между собой; ни внешних адресов,
  ни DNS. Повторять тем же способом при обновлении Gradle, AGP или
  Kotlin (D-18) и заодно убедиться, что сборка не добавляет файлов в
  `~/.gradle/kotlin-profile`: выключатель статистики Kotlin — внутреннее
  свойство, и новая версия может его молча снять.
- **Красный прогон — работа этого изменения**, а не повод повторить
  его «на удачу»: повтор — только если шаг умер до тестов (загрузка,
  нехватка места).
