# Происхождение

Срез на **4 октября 2026**. Всё, что лежит в репозитории или попадает в
сборку, — либо написано для DPpass, либо взято из источника, записанного
здесь, с проверяемой контрольной суммой (D-20). Лицензии тех же
компонентов — `docs/legal/THIRD_PARTY_MATRIX.md`.

Сверку делают проверки DP Verify (D-50, `tools/dpverify.toml`) и
`tools/provenance/check_dependencies.py`: каждая запись
`gradle/libs.versions.toml` и версия Gradle — строка в §2 и §3 с той же
версией, SHA-256 дистрибутива Gradle — как в §3 (`provenance.deps`);
каждый двоичный файл репозитория, в том числе `gradle-wrapper.jar`, —
строка в §4 с его SHA-256 (`provenance.binaries`); каждый модуль
`tools/xray/go.mod` — строка в §2 с той же версией и суммой из `go.sum`;
источники геоданных (`geodata-dlc`, `geodata-dbip`) — строки «Геоданные»
в §2 с той же версией и суммой (`check_dependencies.py`).

## 1. Правила

- **Свой код.** Код, тексты и данные DPpass пишутся для DPpass — людьми
  и ИИ-ассистентами по правилам `CLAUDE.md`. Чужой код, тексты, значки
  и данные не копируются, даже если лицензия позволяет (D-20).
- **Неизвестное происхождение — запрет.** Не принимается: фрагмент «из
  интернета», из ответа на форуме, из чужого репозитория без записи, из
  декомпиляции; фрагмент, который «сгенерировался похожим на проект X»,
  — тоже: он удаляется и пишется заново по описанию нужного свойства.
- **Если чужой фрагмент когда-нибудь понадобится** — сначала решение
  D-NN, затем строка здесь: источник, коммит или версия, лицензия, путь
  в репозитории, SHA-256 исходного файла; уведомление — в матрице.
- **Исследования** (`docs/research/`) — собственный текст с датированными
  ссылками на источники; чужие формулировки не переносятся, результаты
  чужой обратной разработки не используются (`docs/direction/RESEARCH_SCOPE.md`, §4).
- **Данные корпуса** (`tests/data/`) — синтетические (`docs/TESTING.md`,
  «Данные корпуса»), проверяют `data.synthetic` и `security.secrets`.
- **Двоичные файлы** — только записанные в §4. Значки приложения —
  векторные XML собственного рисунка (D-01), растровых изображений нет.

## 2. Зависимости

Откуда сборка берёт каждую запись каталога. Репозитории —
только `google()`, `mavenCentral()` и (для плагинов сборки)
`gradlePluginPortal()`; другие запрещает `code.forbidden` (правило `repositories`).

| Компонент | Версия | Откуда | Проверено (4 октября 2026) |
|---|---|---|---|
| `org.jetbrains.kotlinx:kotlinx-coroutines-core` | 1.11.0 | Maven Central | POM: Apache-2.0; зависимости — `kotlinx-coroutines-core-jvm` 1.11.0, `org.jetbrains:annotations` 23.0.0, `kotlin-stdlib` |
| `org.jetbrains.kotlinx:kotlinx-coroutines-test` | 1.11.0 | Maven Central | POM: Apache-2.0 |
| `org.junit:junit-bom` | 6.1.3 | Maven Central | POM: EPL-2.0; задаёт версию `junit-jupiter` и `junit-platform-launcher` |
| `org.junit.jupiter:junit-jupiter` | 6.1.3 (из `junit-bom`) | Maven Central | POM: EPL-2.0 |
| `org.junit.platform:junit-platform-launcher` | 6.1.3 (из `junit-bom`) | Maven Central | POM: EPL-2.0 |
| `org.junit.vintage:junit-vintage-engine` | 6.1.3 (из `junit-bom`) | Maven Central | 24 октября 2026: POM — EPL-2.0; SHA-1 jar `ee2e019c662152a8cc983bbe0db119a5fae632b9` совпала с опубликованной на Central `.sha1`; SHA-256 jar `37a1e6ade75c09c5385c2830b7cda21c4b1f24a5f36ed7cd7397bc40f7dc71bc` (D-86) |
| `junit:junit` | 4.13.2 | Maven Central | 24 октября 2026: POM — EPL-1.0, зависимость — `org.hamcrest:hamcrest-core` 1.3 (New BSD); SHA-1 jar `8ac9e16d933b6fb43bc7f576336b8f4d7eb5ba12` подтвердил поиск Central по SHA-1 (`junit:junit:4.13.2`); SHA-256 jar `8e495b634469d64fb8acfa3495a065cbacc8a0fff55ce1e31007be4c16dc57d3` (D-86) |
| `org.robolectric:robolectric` | 4.17 | Maven Central | 24 октября 2026: POM — MIT. SHA-256 jar `69e5bc128ba8d1fbb09d36bfb8a617018d6a3a418f77d44b36e7aca6747f14ea` совпала с опубликованной `.sha256`. Транзитивно (лицензии из POM): модули Robolectric 4.17 — MIT, `nativeruntime-dist-compat` 1.0.19 — Apache-2.0; Guava 33.6.0 с `failureaccess`, `listenablefuture`, `error_prone_annotations`, `j2objc-annotations`, `jspecify`, `auto-value-annotations`, `javax.inject`, `test-parameter-injector`, `sqlite4java`, `conscrypt-openjdk-uber` 2.6.2, `snakeyaml` 2.6, `androidx.test:monitor` 1.8.0, `espresso-idling-resource` 3.7.0 — Apache-2.0; ASM 9.10.1 — BSD-3-Clause; `bcprov-jdk18on` 1.85 — Bouncy Castle Licence (MIT-подобная); `icu4j` 78.3 — Unicode-3.0; `javax.annotation-api` 1.3.2 — CDDL-1.1 или GPL-2.0 с classpath exception. Maven Central не отдавал среде сборки jar (404 с `retry-after`), только метаданные и суммы: jar взяты с зеркала Central от Google (`maven-central.storage-download.googleapis.com`), SHA-1 каждого сверена с `.sha1` на Central или поиском Central по SHA-1; не сошлась бы — файл удалён. Суммы SHA-256 всех файлов — в `gradle/verification-metadata.xml`; сверка Gradle — строгая (D-86) |
| `org.robolectric:android-all-instrumented` | 16-robolectric-13921718-i7 | Maven Central | 24 октября 2026: POM — Apache-2.0; образ SDK 36 (Android 16), который ждёт Robolectric 4.17 (`DefaultSdkProvider`: 36 → 16, сборка 13921718; подготовка образа — `i7`); 213 431 622 байта; SHA-1 `d13a33227927de4f98e8f85f91ce68cee55c0ae6` совпала с `.sha1` на Central; SHA-256 `16f1f751643d1d3d5592008846bbdfc1e57cff15e6ec303d26584de3b6ac25ec` (D-86) |
| `org.jetbrains.kotlin:kotlin-gradle-plugin` | 2.4.20 | Maven Central | POM: Apache-2.0 |
| `com.android.tools.build:gradle` | 9.4.1 | Google Maven | POM: Apache-2.0 |
| `org.jetbrains.kotlin.jvm` | 2.4.20 | Maven Central (маркер плагина) | POM маркера: Apache-2.0, ведёт на `kotlin-gradle-plugin` 2.4.20 |
| `com.android.application` | 9.4.1 | Google Maven (маркер плагина) | POM маркера: Apache-2.0, ведёт на `com.android.tools.build:gradle` 9.4.1 |
| `com.pinterest.ktlint:ktlint-cli` | 1.8.0 | Maven Central | 17 октября 2026: POM — MIT; берётся `ktlint-cli-1.8.0-all.jar` (вариант `shadowRuntimeElements`, без зависимостей); SHA-256 jar `369ad2b789f95a011f807e1fcb690ccef80bd7cd014fd139e73ae82dcc0baeab` и `.module` совпали с опубликованными `.sha256` (D-63) |
| `com.google.zxing:core` | 3.5.4 | Maven Central | 18 октября 2026: POM — Apache-2.0 (родитель `zxing-parent` 3.5.4); зависимостей во время выполнения нет; байткод Java 8 (класс 52); SHA-1 jar `955fcd6bcd0723ddfb8ee6ed502d5fdf0e9676a9`, POM `3a0583a864b2eb66e6724b3b0d7dcffc7cf9a5e6` и `zxing-parent` `7d05184913300d086761ca5f5d9850bffae45593` совпали с опубликованными `.sha1`; SHA-256 jar `71de5d89341b5fcf5dd89da7f44e84d825d0e084cdf3ec77c9abe26b0f0ceb13`, POM `502c7368ae869f15428c020a2432eec9dde7436454f3edd1816e0d4b3d0609bf`, `zxing-parent` `9133f322d86101c5c478c08ea3d6734dc376423937ddab1aa2a06aae24fc85c9` — те же, что записал Gradle в `gradle/verification-metadata.xml`. NOTICE — из github.com/zxing/zxing на теге `zxing-3.5.4`: строки об авторских правах Barcode4J и JCommander — в `tools/legal/notices.py` (D-65) |
| `org.jetbrains.kotlin:kotlin-test` | 2.4.20 | Maven Central | POM: Apache-2.0; подключается как `kotlin("test")` |
| `org.jetbrains.kotlin:kotlin-stdlib` | 2.4.20 | Maven Central | POM: Apache-2.0; версию задаёт плагин Kotlin |
| `org.jetbrains:annotations` | 23.0.0 | Maven Central | POM: Apache-2.0; транзитивно (`./gradlew :cli:dependencies`) |

Версии закреплены, содержимое артефактов Gradle сверяет по SHA-256:
`gradle/verification-metadata.xml` (с 6 октября 2026), пересоздаётся
`tools/provenance/update_verification.sh` по чек-листу D-18
(`docs/PROCESS.md`, «Зависимости»).

### Ядро прокси и модули Go (`tools/xray`)

Xray и всё, что нужно для его сборки (D-24). Ядро входит в APK
библиотекой `libdppassxray.so` (мост `tools/xray/bridge` и
`tools/xray/jni`, D-25), в `cli` не попадает. Бинарники в репозиторий
не кладутся: библиотеку для APK собирает задача `xrayNative<Вариант>`
(`tools/xray/native.py android`), ядро и библиотеку для проверок на
хосте — шаги hostcheck «Xray» и «Xray: мост и JNI» (`build/xray/`), из
исходников при каждом прогоне.

| Что | Значение |
|---|---|
| Xray-core | 26.9.30: тег `v26.9.30` в `github.com/XTLS/Xray-core` (upstream, не форк) указывает на коммит `b26a91de4f3294e26a0ad0a970b81a386a41f789` — сверено `git ls-remote` 4 октября 2026; Go-модуль `github.com/xtls/xray-core` той же ревизии — псевдоверсия `v1.260327.1-0.20260930074004-b26a91de4f32` (каталог: `xray`, `xray-go-module`); собранный `xray version` печатает «Xray 26.9.30» |
| Toolchain Go | `golang.org/toolchain` `go1.27.1` — версия из директивы `go` в `tools/xray/go.mod`; `go` 1.21+ скачивает её сам с proxy.golang.org и сверяет с sum.golang.org (`GOTOOLCHAIN=auto` в `check_xray.py`) |
| Откуда модули | proxy.golang.org; каждый архив Go сверяет с суммой `h1:` в `tools/xray/go.sum`, а новую сумму — с журналом sum.golang.org. `check_xray.py` собирает с `-mod=readonly` (суммы не меняются) и отказывается работать, если сверка выключена (`GOSUMDB=off`, `GONOSUMDB`, `GOINSECURE`, `GOPRIVATE`, `GONOPROXY`, `-insecure`) — T10 |
| Android NDK | r30 `30.0.16248370` (каталог: `android-ndk`): `sdkmanager "ndk;30.0.16248370"` с dl.google.com (репозиторий пакетов Android SDK; архив сверяется sdkmanager по SHA-1 из манифеста репозитория); `tools/xray/native.py android` проверяет `Pkg.Revision` в `source.properties` — другая версия NDK не используется. Установлено и проверено 4 октября 2026 |
| Флаг компоновщика `-checklinkname=0` | только для сборки под Android (`tools/xray/native.py`): `github.com/wlynxg/anet` v0.0.5 (транзитивно: Xray finalmask → `pion/stun` → `pion/transport`) в `interface_android.go` ссылается через `//go:linkname` на `net.zoneCache`, а Go 1.23+ такие ссылки запрещает по умолчанию. Модуль не правится (`replace` запрещён); компоновщик по-прежнему проверяет, что символ существует |
| Директивы `replace` | запрещены (`check_dependencies.py`): подмена модуля форком (например, `Happ-proxy/Xray-core`, `docs/legal/THIRD_PARTY_MATRIX.md`, §4) прошла бы мимо этой таблицы |

Модули `require` из `tools/xray/go.mod` (лицензии — `docs/legal/THIRD_PARTY_MATRIX.md`,
§1.7). Сумма — `h1:` архива модуля из `go.sum`; `check_dependencies.py`
сверяет с ней и версию, и сумму: смена `go.sum` без правки этой таблицы
— ошибка. Проверено 4 октября 2026: сборка с `-mod=readonly` и сверкой
sum.golang.org прошла, лицензии прочитаны в архивах этих версий.

| Модуль | Версия | Сумма архива (`go.sum`) |
|---|---|---|
| `github.com/xtls/xray-core` | `v1.260327.1-0.20260930074004-b26a91de4f32` | `h1:Bxo6+07IvdWlqxugsn2/sQrFbR7hjrxRRDMjbOInRho=` |
| `google.golang.org/protobuf` | `v1.36.12` | `h1:pJOKDDOyeXErUroCihFAd5LQuwXBSpVnKGrj5o/fwxc=` |
| `github.com/andybalholm/brotli` | `v1.0.6` | `h1:Yf9fFpf49Zrxb9NlQaluyE92/+X7UVHlhMNJN2sxfOI=` |
| `github.com/apernet/quic-go` | `v0.61.1-0.20260806010916-184d081eef3e` | `h1:5mgtR5gwIgBKMiGI1QdXldZZ+SNor06Nbu1wCBulQBg=` |
| `github.com/cloudflare/circl` | `v1.6.5` | `h1:O64F26HEqNhznd/hrC5KZXVKYuKM2rx4deZDTc4ihQA=` |
| `github.com/ghodss/yaml` | `v1.0.1-0.20220118164431-d8423dcdf344` | `h1:Arcl6UOIS/kgO2nW3A65HN+7CMjSDP/gofXL4CZt1V4=` |
| `github.com/google/btree` | `v1.1.2` | `h1:xf4v41cLI2Z6FxbKm+8Bu+m8ifhj15JuZ9sa0jZCMUU=` |
| `github.com/google/gopacket` | `v1.1.19` | `h1:ves8RnFZPGiFnTS0uPQStjwru6uO6h+nlr9j6fL7kF8=` |
| `github.com/google/uuid` | `v1.6.0` | `h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=` |
| `github.com/gorilla/websocket` | `v1.5.3` | `h1:saDtZ6Pbx/0u+bgYQ3q96pZgCzfhKXGPqt7kZ72aNNg=` |
| `github.com/huin/goupnp` | `v1.2.0` | `h1:uOKW26NG1hsSSbXIZ1IR7XP9Gjd1U8pnLaCMgntmkmY=` |
| `github.com/jackpal/go-nat-pmp` | `v1.0.2` | `h1:KzKSgb7qkJvOUTqYl9/Hg/me3pWgBmERKrTGD7BdWus=` |
| `github.com/juju/ratelimit` | `v1.0.2` | `h1:sRxmtRiajbvrcLQT7S+JbqU0ntsb9W2yhSdNN8tWfaI=` |
| `github.com/klauspost/compress` | `v1.17.4` | `h1:Ej5ixsIri7BrIjBkRZLTo6ghwrEtHFk7ijlczPW4fZ4=` |
| `github.com/klauspost/cpuid/v2` | `v2.4.0` | `h1:S6Hrbc7+ywsr0r+RLapfGBHfyefhCTwEh3A0tV913Dw=` |
| `github.com/koron/go-ssdp` | `v0.0.4` | `h1:1IDwrghSKYM7yLf7XCzbByg2sJ/JcNOZRXS2jczTwz0=` |
| `github.com/kr/text` | `v0.2.0` | `h1:5Nx0Ya0ZqY2ygV366QzturHI13Jq95ApcVaJBhpS+AY=` |
| `github.com/libp2p/go-nat` | `v1.0.1-0.20250821073202-01afc089f138` | `h1:YohuNPT/1k3VcThCQlBZ43PCPWPfMRS1zcxWBF2SLK8=` |
| `github.com/libp2p/go-netroute` | `v0.2.1` | `h1:V8kVrpD8GK0Riv15/7VN6RbUQ3URNZVosw7H2v9tksU=` |
| `github.com/miekg/dns` | `v1.1.73` | `h1:uhT8nJxmTrPJYClxVxTCX+CVn6qnzSiybRk72Z6DgrE=` |
| `github.com/pelletier/go-toml` | `v1.9.5` | `h1:4yBQzkHv+7BHq2PQUZF3Mx0IYxG7LsP222s7Agd3ve8=` |
| `github.com/pion/dtls/v3` | `v3.1.5` | `h1:9xJtVsHwMYeSjPp5Hh1FTis4DchnQWtnOa5o+6ygqfc=` |
| `github.com/pion/logging` | `v0.2.4` | `h1:tTew+7cmQ+Mc1pTBLKH2puKsOvhm32dROumOZ655zB8=` |
| `github.com/pion/stun/v3` | `v3.1.7` | `h1:uRXMTlGLf89WgItGNyZ6aR5jMTX0NBbybXADpQCzn+E=` |
| `github.com/pion/transport/v4` | `v4.1.0` | `h1:8S+nF2reM2cJuqC6g78OVy2BBgmbdns+acx3jA97BvQ=` |
| `github.com/pires/go-proxyproto` | `v0.15.0` | `h1:dTshmNbFm/D+0+sbrxUuddPOZ5Y0B7c5NhtsBkm6LqI=` |
| `github.com/quic-go/qpack` | `v0.6.0` | `h1:g7W+BMYynC1LbYLSqRt8PBg5Tgwxn214ZZR34VIOjz8=` |
| `github.com/refraction-networking/utls` | `v1.8.3-0.20260301010127-aa6edf4b11af` | `h1:er2acxbi3N1nvEq6HXHUAR1nTWEJmQfqiGR8EVT9rfs=` |
| `github.com/robfig/cron/v3` | `v3.0.1` | `h1:WdRxkvbJztn8LMz/QEvLN5sBU+xKpSqwwUO1Pjr4qDs=` |
| `github.com/vishvananda/netlink` | `v1.3.1` | `h1:3AEMt62VKqz90r0tmNhog0r/PpWKmrEShJU0wJW6bV0=` |
| `github.com/vishvananda/netns` | `v0.0.5` | `h1:DfiHV+j8bA32MFM7bfEunvT8IAqQ/NzSJHtcmW5zdEY=` |
| `github.com/wlynxg/anet` | `v0.0.5` | `h1:J3VJGi1gvo0JwZ/P1/Yc/8p63SoW98B5dHkYDmpgvvU=` |
| `github.com/xtls/reality` | `v0.0.0-20260908062103-8cdf7bf9c7f0` | `h1:rb+fKQFhz+5I2PPuQsNYxI5mUU840XWYtRF0ZBjvkws=` |
| `go4.org/netipx` | `v0.0.0-20231129151722-fdeea329fbba` | `h1:0b9z3AuHCjxk0x/opv64kcgZLBseWJUpBw5I82+2U4M=` |
| `golang.org/x/crypto` | `v0.57.0` | `h1:3ZVCjf8Ggz7zneR/EHRVx68Ctf+2pmIMP2UFhh9cC6M=` |
| `golang.org/x/exp` | `v0.0.0-20240506185415-9bf2ced13842` | `h1:vr/HnozRka3pE4EsMEg1lgkXJkTFJCVUX+S/ZT6wYzM=` |
| `golang.org/x/net` | `v0.59.0` | `h1:5zfYln+w5XCxwrnMMJPufRgNoXEaGxl0wo5GqPXyues=` |
| `golang.org/x/sync` | `v0.23.0` | `h1:KameEIfc1IkluZyXWLn39Wd4tURc6GbCiISGiZm2bQk=` |
| `golang.org/x/sys` | `v0.48.0` | `h1:bbX/i/6MgT9BVLM9RT1thmxL04yeTAhbEz4SyadbXoo=` |
| `golang.org/x/text` | `v0.42.0` | `h1:JbOZXgfeCPU9gacVtYliJqOhD+zhrEqK4LfdpmlUZqI=` |
| `golang.org/x/time` | `v0.14.0` | `h1:MRx4UaLrDotUKUdCIqzPC48t1Y9hANFKIRpNx+Te8PI=` |
| `golang.zx2c4.com/wintun` | `v0.0.0-20230126152724-0fa3db229ce2` | `h1:B82qJJgjvYKsXS9jeunTOisW56dUokqW/FOteYJJ/yg=` |
| `golang.zx2c4.com/wireguard` | `v0.0.0-20250521234502-f333402bd9cb` | `h1:whnFRlWMcXI9d+ZbWg+4sHnLp52d5yiIPUxMBSt4X9A=` |
| `golang.zx2c4.com/wireguard/windows` | `v1.1.1` | `h1:8/H97U1v1PNDNcBsMZgU3KFuND9MQdTsU2NOwmCXArE=` |
| `google.golang.org/genproto/googleapis/rpc` | `v0.0.0-20260706201446-f0a921348800` | `h1:qEHAMpSaUhtD0p3NbEEI83HwNGFxEwaSJ1G9PLnCBZE=` |
| `google.golang.org/grpc` | `v1.84.0` | `h1:soMyaPJ8pAak5PIQ0DGBUir0XRo2fRoMqhNWMLlLxO0=` |
| `gopkg.in/yaml.v2` | `v2.4.0` | `h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=` |
| `gvisor.dev/gvisor` | `v0.0.0-20260122175437-89a5d21be8f0` | `h1:Lk6hARj5UPY47dBep70OD/TIMwikJ5fGUGX0Rm3Xigk=` |
| `lukechampine.com/blake3` | `v1.4.1` | `h1:I3Smz7gso8w4/TunLKec6K2fn+kyKtDxr/xcQEN84Wg=` |

### Геоданные (D-27, D-31)

Источники набора геоданных — данные, а не код. Набор собирает свой
сборщик `tools/xray/geodata` (Go, тот же `tools/xray/go.mod`); сборку
запускает `tools/xray/geodata.py`, на хосте — шаг hostcheck «Xray:
геоданные», в APK — задача `:app` `xrayGeodata<Вариант>`; набор в APK
сверяет `check_apk.py`. Версии — в каталоге (`geodata-dlc`, `geodata-dbip`). Суммы
ниже сверяют `geodata.py` при сборке и `check_dependencies.py`.

| Источник | Версия | Откуда и сумма |
|---|---|---|
| `github.com/v2fly/domain-list-community` | `v0.0.0-20261004053103-63777333b7dd` | Go-модуль с proxy.golang.org: `go mod download` со сверкой sum.golang.org (`goenv.py`); коммит `63777333b7dd1ac57f790e466c0f6a647b9c7281` upstream `v2fly/domain-list-community`; сумма архива `h1:xgYZcK6tuBB3nhq/Wg7sHax7SDjGD+XGFDDZaj/By0I=`; лицензия — `LICENSE` в архиве (MIT) |
| DB-IP «IP to Country Lite» | `2026-10` | `download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz` (выпуск 1 октября 2026), загружен 5 октября 2026; лежит в репозитории без изменений — `tools/xray/geodata/sources/dbip-country-lite-2026-10.csv.gz`, SHA-256 — §4. Лицензия CC BY 4.0: IP Geolocation by DB-IP (https://db-ip.com) |
| Таблица `private` | — | своя: реестры особых адресов IANA (IPv4, IPv6; RFC 6890), сверено 5 октября 2026 по www.iana.org/assignments, и групповые адреса (RFC 5771, RFC 4291); записана своими словами в `tools/xray/geodata/private.go` |

Проверено 5 октября 2026: набор собран (`geodata.py --test`), ядро
Xray 26.9.30 его принимает и выбирает по его кодам
(`TestXrayAcceptsTheSet`, ручная проверка `dppass-xray-probe route` на
полном наборе).

### Windows (D-97)

Архивы для сборки Windows — не в репозитории: их скачивает
`tools/desktop/windows_deps.py` и сверяет с суммами ниже (сумма не
совпала — архив удаляется, сборка останавливается). Версии — в каталоге
(`temurin-windows`, `wintun`); сверяет и `check_dependencies.py`.
Скачаны и сверены 30 октября 2026 (`docs/research/WINDOWS_SHELL.md`,
§3–§4).

| Архив | Версия | Откуда и сумма |
|---|---|---|
| `OpenJDK21U-jdk_x64_windows_hotspot_21.0.13_9.zip` | `21.0.13+9` | Eclipse Temurin, `github.com/adoptium/temurin21-binaries`, выпуск `jdk-21.0.13+9` (`JAVA_VERSION_DATE` 2026-10-20); 205 421 281 байт; SHA-256 `a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9` — та же, что у `api.adoptium.net` 30.10.2026. Берутся `include/` (заголовки JNI моста) и `jmods/` (рантайм jlink комплекта со своим `legal/`) |
| `wintun-0.14.1.zip` | `0.14.1` | `www.wintun.net/builds/wintun-0.14.1.zip`; SHA-256 `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51` — та же, что на странице `www.wintun.net` 30.10.2026. В комплект — `bin/amd64/wintun.dll` (427 552 байта) и `LICENSE.txt` без изменений |

Инструменты сборки комплекта — пакеты Ubuntu, не в репозитории:
`gcc-mingw-w64-x86-64-posix` 13.2.0-6ubuntu1+26.1,
`binutils-mingw-w64-x86-64` 2.41.90.20240122-1ubuntu1+11.4 (`windres`),
`mingw-w64-x86-64-dev` 11.0.1-3build1 (среда выполнения C — статически
в `dppass.exe` и DLL моста, матрица §1.9), `wine64` 9.0~repack-4build3
(только проверка). Запускатель `dppass.exe` — свой код
(`desktop/windows/`), собирается из исходника при каждой сборке
комплекта; двоичного в репозитории нет. Рантайм `runtime\` — `jlink`
хоста из `jmods/` архива Temurin выше, без своих изменений.

## 3. Gradle

| Что | Значение |
|---|---|
| `gradle` | 9.8.0 — версия дистрибутива из `gradle-wrapper.properties`; её сверяет `provenance.deps` DP Verify (D-50) |
| Дистрибутив | `gradle-9.8.0-bin.zip` с `services.gradle.org/distributions/` |
| SHA-256 дистрибутива | `bafd5ce9cfaea0fbccfdc8439a1ac42fbd4cd9c89dc9a988228d8a2639a58e6c` — совпадает с опубликованным `gradle-9.8.0-bin.zip.sha256`; записан в `gradle/wrapper/gradle-wrapper.properties` (`distributionSha256Sum`), wrapper сверяет его при загрузке |
| SHA-256 `gradle-wrapper.jar` | `238e777fcddd7e34f9708186085def2abd6e08e658505b38718d79d74c21abd5` — совпадает с опубликованным `gradle-9.8.0-wrapper.jar.sha256` |
| `gradlew`, `gradlew.bat`, `gradle-wrapper.properties` | побайтно совпадают с результатом `gradle wrapper --gradle-version 9.8.0 --distribution-type bin --gradle-distribution-sha256-sum …`, выполненного дистрибутивом 9.8.0 |

Сверено 4 октября 2026. Обновление Gradle — по чек-листу D-18
(`docs/PROCESS.md`, «Зависимости»): обе суммы берутся с
`services.gradle.org` и записываются здесь в том же изменении.

## 4. Двоичные файлы

| Файл | SHA-256 | Откуда |
|---|---|---|
| `gradle/wrapper/gradle-wrapper.jar` | `238e777fcddd7e34f9708186085def2abd6e08e658505b38718d79d74c21abd5` | Gradle 9.8.0 (§3) |
| `tools/xray/geodata/sources/dbip-country-lite-2026-10.csv.gz` | `097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80` | DB-IP «IP to Country Lite» 2026-10 (§2, «Геоданные»), без изменений; IP Geolocation by DB-IP (https://db-ip.com), CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/) |

Других двоичных файлов в репозитории нет. Новый — строка здесь с
источником и SHA-256 в том же изменении, иначе `provenance.binaries`
не пропустит.

## 5. Тексты

| Файл | Происхождение |
|---|---|
| `LICENSE` | «все права защищены» — написан для DPmetaApp (`DPmetaApp:D-47`), с оговоркой о стороннем и копии DP Verify; до 30 октября 2026 — текст Apache License 2.0 (D-96) |
| Остальные документы, комментарии, сообщения диагностики | написаны для DPpass |

## 6. Внешние исходники для исследований

Повторяемые описи (`tools/research/happ_inventory.sh`) клонируют чужие
публичные репозитории в `third_party/` — каталог вне репозитория
(`.gitignore`). Оттуда в DPpass ничего не копируется: опись печатает
состав, выводы записываются своими словами в `docs/research/` с датой.

## 7. Ключ подписи тестовых сборок

Тестовые сборки для устройств автора (D-35) подписываются ключом
разработчика `dppass-dev` (RSA 4096, хранилище PKCS12). Ключ — у автора,
в репозитории его нет (`security.secrets` не пропускает файлы ключей).
Сборка получает его из переменных окружения, подписывает
`tools/release/sign_apks.py` и сверяет сертификат подписи с отпечатком
ниже: APK, подписанный другим ключом, не выходит.

Ключ создан 6 октября 2026 на устройстве автора (OpenSSL, Termux);
отпечаток ниже прислал автор. Автор проверяет APK так:
`apksigner verify --print-certs <APK>` — строка `Signer #1 certificate SHA-256 digest` совпадает с отпечатком
(без двоеточий, строчными буквами). Ключ для магазинов (этап 5) —
другой.

| Ключ | SHA-256 сертификата |
|---|---|
| `dppass-dev` | 807cc957c376a09c9363d99ce05a1f5b9005f213ca3a1923db58b646a761e64f |

## 8. Копия DP Verify (`tools/dpv/`)

Общий каркас проверок автора (D-50) — свой код автора из его репозитория
DP-Verify, поставлен копией; руками не правится, правка — в DP-Verify и
новой поставкой. Лицензия копии — DP Verify (`DP-Verify:V-15`), не
`LICENSE` DPpass (D-96, `DPmetaApp:D-47`). Каждый файл копии сверяет с манифестом проверка
`dpv.integrity`.

| Копия | Версия | Источник | SHA-256 манифеста |
|---|---|---|---|
| `tools/dpv/` | 1.0.0-rc2 | `dpsmpx/DP-Verify@938f68017a970049596b76892cb4f06be8e621fe` | `a2fae9e34198a01ad50c2768eb7839194fdbd4e367c61cfbfbc4eb50fbab1fac` |
