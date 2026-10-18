# Матрица лицензий сторонних компонентов

Срез на **4 октября 2026**. Каждый сторонний компонент, который
попадает в приложение, в `cli`, в сборку или в тесты, — строка
здесь с лицензией и статусом (D-20). Что сборка реально берёт, сверяет
`tools/provenance/check_dependencies.py`: каждая запись
`gradle/libs.versions.toml` и каждый модуль `tools/xray/go.mod` должны
иметь строку с **той же версией**, иначе hostcheck падает. Откуда взят компонент и как проверен —
`docs/PROVENANCE.md`.

Статусы:

- **разрешён** — используется; версия закреплена (каталог, wrapper).
- **запланирован** — решение принято, версия ещё не выбрана; в сборку
  не попадает, пока строка не переведена в «разрешён» по чек-листу D-18
  (`docs/PROCESS.md`, «Зависимости»).
- **рассматривается** — вариант для отложенного решения
  (`docs/direction/DECISIONS.md`, «Отложено»); не используется до решения.
- **запрещён** — не используется ни в каком виде; основание — в строке.

Лицензии библиотек сверены по POM опубликованной версии
(Maven Central, Google Maven), Gradle — по `LICENSE` дистрибутива,
модули Go — по файлам лицензии в архиве модуля той версии, что
закреплена в `tools/xray/go.sum`; все — 4 октября 2026.

## 1. Разрешённые

### 1.1. Приложение и `cli`

То, что попадает в APK и в дистрибутив `cli`. Уведомления этих
компонентов показываются в приложении с этапа 5 (`docs/direction/ROADMAP/05-release.md`).

| Компонент | Версия | Лицензия | Куда | Статус | Зачем |
|---|---|---|---|---|---|
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` (JVM-артефакт — `kotlinx-coroutines-core-jvm`; `kotlinx-coroutines-bom` — только выравнивание версий) | 1.11.0 | Apache-2.0 | APK, `cli`, ядро (`connection`) | разрешён | `suspend` на границах ядра, проб, здоровья, загрузки (`docs/ARCHITECTURE.md`, §12) |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.4.20 | Apache-2.0 | APK, `cli`, все модули | разрешён | стандартная библиотека Kotlin; версию задаёт плагин Kotlin, не каталог |
| `org.jetbrains:annotations` | 23.0.0 | Apache-2.0 | APK, `cli` (транзитивно от корутин и `kotlin-stdlib`) | разрешён | аннотации `@NotNull`/`@Nullable`; исполняемого кода нет |
| `com.google.zxing:core` | 3.5.4 | Apache-2.0 | APK (`app`) | разрешён | распознавание QR с картинки (D-65); без зависимостей; NOTICE проекта (части Barcode4J) — в уведомлениях APK |

### 1.2. Тесты

В APK и `cli` не попадает: только `testImplementation`/`testRuntimeOnly`.

| Компонент | Версия | Лицензия | Куда | Статус | Зачем |
|---|---|---|---|---|---|
| `org.jetbrains.kotlinx:kotlinx-coroutines-test` | 1.11.0 | Apache-2.0 | тесты `connection` | разрешён | виртуальное время корутин в тестах |
| `org.jetbrains.kotlin:kotlin-test` | 2.4.20 | Apache-2.0 | тесты всех модулей | разрешён | утверждения; подключается как `kotlin("test")`, версия = версии Kotlin |
| `org.junit:junit-bom` | 6.1.3 | EPL-2.0 | тесты | разрешён | только выравнивает версии JUnit |
| `org.junit.jupiter:junit-jupiter` | 6.1.3 | EPL-2.0 | тесты | разрешён | JUnit Jupiter: тесты, динамические тесты корпуса |
| `org.junit.platform:junit-platform-launcher` | 6.1.3 | EPL-2.0 | тесты | разрешён | запуск JUnit Platform из Gradle |

EPL-2.0 — слабый копилефт на уровне модуля; тестовые библиотеки не
распространяются вместе с DPpass, обязательств для APK нет.

### 1.3. Сборка

В APK не попадает — кроме того, что добавляет сам D8 из AGP: несколько
вспомогательных классов desugaring (`com.android.tools.r8.*`) и
синтетические заглушки классов платформы новее minSdk; состав кода в
APK проверяет `check_apk.py`. Транзитивные зависимости инструментов
сборки (у AGP их десятки) отдельными строками не записываются: они не распространяются,
а их лицензии — в POM самих инструментов. Отдельная строка нужна тому,
что попадает в APK или в `cli`.

| Компонент | Версия | Лицензия | Куда | Статус | Зачем |
|---|---|---|---|---|---|
| `gradle` (Gradle Build Tool, через wrapper) | 9.8.0 | Apache-2.0 | сборка | разрешён | сборка; SHA-256 дистрибутива и wrapper — `docs/PROVENANCE.md` |
| `org.jetbrains.kotlin:kotlin-gradle-plugin` | 2.4.20 | Apache-2.0 | сборка (`build-logic`) | разрешён | компилятор Kotlin; convention-плагины |
| `org.jetbrains.kotlin.jvm` | 2.4.20 | Apache-2.0 | сборка | разрешён | id плагина Kotlin/JVM (запись `[plugins]` каталога; реализация — `kotlin-gradle-plugin` той же версии) |
| `com.android.tools.build:gradle` | 9.4.1 | Apache-2.0 | сборка (`build-logic`) | разрешён | Android Gradle Plugin: сборка APK, D8, Android Lint (и для JVM-модулей) |
| `com.android.application` | 9.4.1 | Apache-2.0 | сборка | разрешён | id плагина приложения (запись `[plugins]` каталога; реализация — AGP той же версии) |
| `com.pinterest.ktlint:ktlint-cli` (классификатор `all` — один файл со своими зависимостями внутри) | 1.8.0 | MIT | проверка стиля (`ktlintCheck`, `ktlintFormat`) | разрешён | форматтер Kotlin (D-63); в APK и `cli` не попадает |

### 1.4. CI

Нет. GitHub Actions не используется и не запускается (D-23), сторонних
действий CI в цепочке поставки нет.

### 1.5. Инструменты вне репозитория

Ставятся на машину разработчика, в репозиторий и в APK не
попадают; версии — `docs/PROCESS.md`, «Проверки».

| Инструмент | Лицензия | Где |
|---|---|---|
| JDK 21 (например, OpenJDK или Eclipse Temurin) | GPL-2.0 с Classpath Exception | сборка, тесты |
| Android SDK (платформа 36, build-tools) | Android Software Development Kit License Agreement | сборка `app`, `check_android_api.py`; не распространяется |
| Python 3.11+ | PSF-2.0 | скрипты проверок `tools/` |
| Go 1.21+ (сам скачивает toolchain `go1.27.1` по `tools/xray/go.mod`, `docs/PROVENANCE.md`, §2) | BSD-3-Clause | шаг hostcheck «Xray»: сборка ядра и `dppass-xray-probe`; сборка библиотеки ядра `libdppassxray` (`tools/xray/native.py`, D-25). Среда выполнения Go входит в библиотеку — §1.7 |
| Android NDK r30 (`30.0.16248370`, `android-ndk` в каталоге) | Android Software Development Kit License Agreement; инструменты LLVM — Apache-2.0 with LLVM Exception | cgo-компилятор и sysroot для `GOOS=android` (`tools/xray/native.py android`). Библиотека зависит только от системных `libc.so`, `libdl.so`, `liblog.so` устройства; из NDK в APK попадают разве что встроенные функции компилятора (compiler-rt, исключение LLVM — без обязательств для двоичного кода) |

### 1.6. Ядро прокси

| Компонент | Версия | Лицензия | Куда | Статус | Основание |
|---|---|---|---|---|---|
| `XTLS/Xray-core` (только upstream, не форки) | 26.9.30 | MPL-2.0 | APK — библиотека `libdppassxray.so` (мост `tools/xray/bridge` и `tools/xray/jni`, D-25); проверка компилятора на хосте (`tools/xray`) | разрешён | D-03, D-24, D-25, `docs/research/BACKEND_STRATEGY.md` |

Обязательства MPL-2.0 — файловые: изменённые файлы самого Xray
открываются под MPL-2.0, код DPpass не затрагивается; в приложении —
уведомление и где взять исходники (этап 5). DPpass файлы Xray не
меняет: ядро собирается из модуля upstream как есть.

### 1.7. Модули Go ядра и его проверки (`tools/xray`)

Всё, что `tools/xray/go.mod` требует для сборки upstream `xray`,
собственного `dppass-xray-probe` (D-24) и библиотеки ядра
`libdppassxray` (D-25). **Распространяются в APK:** библиотека ядра
статически компонует все модули таблицы, кроме помеченных «в сборку не
входит», — 46 модулей; состав для Android и для хоста одинаков
(`go list -deps ./jni` для `GOOS=android` и `GOOS=linux`, 4 октября
2026). В `cli` модули не попадают. Состав и версии задаёт Xray 26.9.30;
DPpass их не выбирает, но записывает и сверяет каждую. «Кто
использует» — пакет, через который модуль попадает в сборку
(`go mod why -m`). Модули с пометкой «в сборку не входит» есть в графе
модулей, но не компилируются на Linux (только Windows или только тесты
чужого модуля).

| Модуль | Версия | Лицензия | Кто использует | Статус |
|---|---|---|---|---|
| `github.com/xtls/xray-core` | `v1.260327.1-0.20260930074004-b26a91de4f32` | MPL-2.0 | само ядро (тег `v26.9.30`, §1.6) | разрешён |
| `google.golang.org/protobuf` | `v1.36.12` | BSD-3-Clause | `dppass-xray-probe` (синтетические геоданные), сборщик набора геоданных `dppass-geodata` (D-27), конфигурация ядра | разрешён |
| `github.com/andybalholm/brotli` | `v1.0.6` | MIT | `app/dns` | разрешён |
| `github.com/apernet/quic-go` | `v0.61.1-0.20260806010916-184d081eef3e` | MIT | `app/dns` (QUIC: DoQ, Hysteria2) | разрешён |
| `github.com/cloudflare/circl` | `v1.6.5` | BSD-3-Clause | `main/commands/all` (криптография) | разрешён |
| `github.com/ghodss/yaml` | `v1.0.1-0.20220118164431-d8423dcdf344` | MIT | `infra/conf/serial` (конфигурация в YAML) | разрешён |
| `github.com/google/btree` | `v1.1.2` | Apache-2.0 | `proxy/wireguard` (через gVisor) | разрешён |
| `github.com/google/gopacket` | `v1.1.19` | BSD-3-Clause | `transport/internet/finalmask/realm` | разрешён |
| `github.com/google/uuid` | `v1.6.0` | BSD-3-Clause | `infra/conf` | разрешён |
| `github.com/gorilla/websocket` | `v1.5.3` | BSD-2-Clause | `transport/internet/websocket` | разрешён |
| `github.com/huin/goupnp` | `v1.2.0` | BSD-2-Clause | `transport/internet/finalmask/realm` | разрешён |
| `github.com/jackpal/go-nat-pmp` | `v1.0.2` | Apache-2.0 | `transport/internet/finalmask/realm` | разрешён |
| `github.com/juju/ratelimit` | `v1.0.2` | LGPL-3.0 с исключением для статической и динамической компоновки | `github.com/xtls/reality` (REALITY) | разрешён (в APK — с уведомлением и ссылкой на исходники библиотеки, этап 5) |
| `github.com/klauspost/compress` | `v1.17.4` | BSD-3-Clause; части — Apache-2.0, MIT | `app/dns` | разрешён |
| `github.com/klauspost/cpuid/v2` | `v2.4.0` | MIT | `common/utils` | разрешён |
| `github.com/koron/go-ssdp` | `v0.0.4` | MIT | `transport/internet/finalmask/realm` | разрешён |
| `github.com/kr/text` | `v0.2.0` | MIT | тесты `gopkg.in/yaml.v2`; в сборку не входит | разрешён |
| `github.com/libp2p/go-nat` | `v1.0.1-0.20250821073202-01afc089f138` | Apache-2.0 | `transport/internet/finalmask/realm` | разрешён |
| `github.com/libp2p/go-netroute` | `v0.2.1` | BSD-3-Clause | `transport/internet/finalmask/realm` | разрешён |
| `github.com/miekg/dns` | `v1.1.73` | BSD-3-Clause | `transport/internet/tls` | разрешён |
| `github.com/pelletier/go-toml` | `v1.9.5` | MIT; два файла — Apache-2.0 | `infra/conf/serial` (конфигурация в TOML) | разрешён |
| `github.com/pion/dtls/v3` | `v3.1.5` | MIT; части — CC0-1.0 | `transport/internet/finalmask/realm` | разрешён |
| `github.com/pion/logging` | `v0.2.4` | MIT | `transport/internet/finalmask/realm` | разрешён |
| `github.com/pion/stun/v3` | `v3.1.7` | MIT; части — BSD-3-Clause, CC0-1.0 | `transport/internet/finalmask/realm` | разрешён |
| `github.com/pion/transport/v4` | `v4.1.0` | MIT; части — BSD-3-Clause | `transport/internet/finalmask/realm` | разрешён |
| `github.com/pires/go-proxyproto` | `v0.15.0` | Apache-2.0 | `transport/internet` | разрешён |
| `github.com/quic-go/qpack` | `v0.6.0` | MIT | `transport/internet/masque` | разрешён |
| `github.com/refraction-networking/utls` | `v1.8.3-0.20260301010127-aa6edf4b11af` | BSD-3-Clause | `app/dns`, отпечаток TLS | разрешён |
| `github.com/robfig/cron/v3` | `v3.0.1` | MIT | `infra/conf` | разрешён |
| `github.com/vishvananda/netlink` | `v1.3.1` | Apache-2.0 | `proxy/wireguard` | разрешён |
| `github.com/vishvananda/netns` | `v0.0.5` | Apache-2.0 | `proxy/wireguard` | разрешён |
| `github.com/wlynxg/anet` | `v0.0.5` | BSD-3-Clause | `transport/internet/finalmask/realm` | разрешён |
| `github.com/xtls/reality` | `v0.0.0-20260908062103-8cdf7bf9c7f0` | MPL-2.0; части из Go — BSD-3-Clause | REALITY | разрешён |
| `go4.org/netipx` | `v0.0.0-20231129151722-fdeea329fbba` | BSD-3-Clause | `common/geodata` | разрешён |
| `golang.org/x/crypto` | `v0.57.0` | BSD-3-Clause | `proxy/shadowsocks` и др. | разрешён |
| `golang.org/x/exp` | `v0.0.0-20240506185415-9bf2ced13842` | BSD-3-Clause | `transport/internet/hysteria/congestion/bbr` | разрешён |
| `golang.org/x/net` | `v0.59.0` | BSD-3-Clause | `app/dns` и др. | разрешён |
| `golang.org/x/sync` | `v0.23.0` | BSD-3-Clause | `app/dns` | разрешён |
| `golang.org/x/sys` | `v0.48.0` | BSD-3-Clause | `common/net` | разрешён |
| `golang.org/x/text` | `v0.42.0` | BSD-3-Clause | `common/geodata/strmatcher` | разрешён |
| `golang.org/x/time` | `v0.14.0` | BSD-3-Clause | `proxy/wireguard` | разрешён |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | MIT | `proxy/tun` (только Windows); в сборку не входит | разрешён |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20250521234502-f333402bd9cb` | MIT | `proxy/wireguard` | разрешён |
| `golang.zx2c4.com/wireguard/windows` | `v1.1.1` | MIT | `proxy/tun` (только Windows); в сборку не входит | разрешён |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20260706201446-f0a921348800` | Apache-2.0 | `app/log/command` (gRPC) | разрешён |
| `google.golang.org/grpc` | `v1.84.0` | Apache-2.0 | `app/commander`, транспорт gRPC | разрешён |
| `gopkg.in/yaml.v2` | `v2.4.0` | Apache-2.0; части из libyaml — MIT | `infra/conf/serial` | разрешён |
| `gvisor.dev/gvisor` | `v0.0.0-20260122175437-89a5d21be8f0` | Apache-2.0 | `proxy/wireguard`, `proxy/tun` (сетевой стек) | разрешён |
| `lukechampine.com/blake3` | `v1.4.1` | MIT | `main/commands/all` (BLAKE3) | разрешён |

Копилефта, который распространялся бы на код DPpass, здесь нет: MPL-2.0
— файловый; у `juju/ratelimit` LGPL-3.0 с исключением, которое
разрешает распространять статически или динамически скомпонованную
программу без минимального соответствующего исходного кода и сведений
об установке (п. 4d и 4e LGPL-3.0); остальные обязательства LGPL-3.0
(текст лицензии, уведомление, доступность исходников самой библиотеки)
— уведомления о лицензиях в приложении, этап 5. Модули функций Xray вне
IR v1 (например, WireGuard) в библиотеке есть: их тянет разбор JSON
Xray (`infra/conf`), а не DPpass, и отсечь их без правки upstream
нельзя; запустить их конфигурацией не даёт политика моста (D-25).

### 1.8. Геоданные (D-27, D-31)

Данные, а не код. Набор (`geoip.dat`, `geosite.dat`) собирает свой
сборщик `tools/xray/geodata` из этих источников (`tools/xray/geodata.py`),
в APK его кладёт задача `:app` `xrayGeodata<Вариант>` (`assets/geodata/`,
сжатыми файлами). Рядом с набором лежит `NOTICE.txt`: атрибуция DB-IP и
уведомление MIT dlc (его текст — из `LICENSE` архива модуля). На экране
лицензий — этап 5. Лицензии проверены 4 октября 2026
по `LICENSE` репозитория (dlc) и странице загрузки базы (DB-IP), сверены
5 октября 2026 по `LICENSE` в архиве модуля закреплённой версии. Версии
и суммы — каталог и `docs/PROVENANCE.md`, §2 «Геоданные».

| Компонент | Версия | Лицензия | Куда | Статус | Условия |
|---|---|---|---|---|---|
| `github.com/v2fly/domain-list-community` (dlc) | `v0.0.0-20261004053103-63777333b7dd` | MIT | APK — `assets/geodata/geosite.dat`: все списки, в том числе `category-ru` и `category-gov-ru` | разрешён | уведомление MIT — `NOTICE.txt` рядом с набором и экран лицензий (этап 5) |
| DB-IP «IP to Country Lite» | `2026-10` | CC BY 4.0 | APK — `assets/geodata/geoip.dat`: все страны; исходный CSV — в репозитории (D-31) | разрешён | атрибуция «IP Geolocation by DB-IP» со ссылкой на https://db-ip.com и указание изменений — `NOTICE.txt` рядом с набором и экран лицензий (этап 5); распространять можно, устаревшие версии удалять не требуется |

## 2. Запланированные

Нет.

## 3. Рассматриваемые

Нет. `heiher/hev-socks5-tunnel` (MIT) рассматривался как мост fd → ядро
и отклонён D-30 (§4).

## 4. Запрещённые

| Что | Лицензия | Почему нельзя |
|---|---|---|
| sing-box, libbox (`SagerNet/sing-box`) в одном процессе с приложением | GPL-3.0-or-later с условием об имени | весь APK стал бы производным под GPL (D-20); второе ядро — отложенное решение |
| Код клиентов v2rayNG, NekoBox, sing-box for Android, Hiddify, Amnezia VPN | GPL-3.0 (у Hiddify — с дополнительными условиями) | DPpass пишет свой код (D-20); сравнение — только как факт (`docs/research/COMPETITOR_ARCHITECTURE.md`) |
| Собственные репозитории и документация Happ (`Happ-proxy/*`, `HappDev/happ_su`, `www.happ.su`) | нет лицензии — все права защищены | `docs/research/HAPP_SOURCE_AUDIT.md`, §0 и §4 |
| Форк `Happ-proxy/Xray-core` как источник Xray | MPL-2.0 (upstream) | источник Xray — только `XTLS/Xray-core` (`docs/research/HAPP_SOURCE_AUDIT.md`, §4) |
| Тексты `XTLS/Xray-docs-next` и его форков | CC-BY-SA-4.0 | тексты не копируются (D-20) |
| Эталонная реализация AnyTLS (`anytls-go`) | нет лицензии | `docs/research/TRANSPORT_COMPARISON.md` |
| `XTLS/libXray` как обёртка ядра | MIT | отклонён D-25: своя обёртка Go с JNI (`tools/xray/bridge`, `tools/xray/jni`); libXray несёт разбор ссылок, пинг и правку геоданных, которые DPpass делает сам или не поручает ядру |
| `heiher/hev-socks5-tunnel` как мост fd → ядро | MIT | отклонён D-30: мост — вход TUN Xray; hev передаёт трафик ядру через вход SOCKS, а политика моста допускает только TUN (T11) |
| Базы MaxMind GeoLite2 (`GeoLite2-Country` и др.), в том числе в чужих `geoip.dat` | GeoLite2 EULA | передача данных третьим лицам — только с согласия MaxMind (§6.1), устаревшие версии требуется уничтожать (§6.3): с данными в APK у пользователей несовместимо (D-27; проверено 4 октября 2026) |
| Готовые `geoip.dat`/`geosite.dat` других проектов | — | набор собирается своим кодом из первичных источников (D-27, D-20) |
| Результаты обратной разработки закрытых клиентов (Happwner и др.) | — | `docs/direction/RESEARCH_SCOPE.md`, §4 |
| SDK аналитики, отчётов о падениях, push-уведомлений (Firebase, Sentry и подобные) | — | без телеметрии и идентификаторов (D-12) |

## 5. Как меняется матрица

- Новая библиотека, плагин или версия — строка здесь и в
  `docs/PROVENANCE.md` в том же изменении, что и каталог; без них
  `check_dependencies.py` не пропустит сборку.
- Перевод из «запланирован» или «рассматривается» в «разрешён» — только
  по чек-листу D-18 (`docs/PROCESS.md`, «Зависимости»), для ядра — с
  `capabilityDiff`.
- Смена лицензии компонента при обновлении — повод остановиться и
  пересмотреть строку, а не обновить молча.
