# Тестирование DPpass

Всё, что можно проверить без устройства, проверяется на хосте
(D-21; CI нет — D-23). Запуск — `tools/hostcheck/run.sh` (`docs/PROCESS.md`, «Проверки»);
только тесты — `./gradlew build`.

## 1. Слои

| Слой | Где | Что проверяет |
|---|---|---|
| Модульные тесты | `<модуль>/src/test` | каждый модуль отдельно: разбор, проверка, нормализация, маршрутизация, DNS, классификация сети, бюджет проб, хранилище, подписки, активация, план, оркестратор, спецификация TUN; журнал устройства (D-26): запись в фоне, части, прошлый сеанс, текст для буфера обмена, запись о падении (`FileLogSinkTest`, `LogExportTest`, `CrashRecordTest`); политика пользователя (D-38: `PolicyBuilderTest` — решения `RouteEvaluator` по набору геоданных, `PolicyStoreTest`, `PolicyServiceTest`), расписание и хранение подписок (D-39: `UpdateScheduleTest`, `SubscriptionCodecTest`), задержка (D-41: `LatencyBookTest`), импорт (D-42: `ImportClassifierTest`), подписки в хранилище (`SubscriptionBookTest`, `SubscriptionFlowTest`); адаптивная устойчивость (D-44: `StabilityModelTest` — пессимизм, джиттер, смена режима, гистерезис, устойчивость к одиночному сбою; `TransportAdvisorTest` — перенос опыта; `SessionSupervisorTest`; `StabilityBookTest` — хранение без секретов; `CandidatePlannerTest.learnedStabilityOrdersViableCandidates`; сбой выбранного сервера — D-58: `DegradationTest` — отказ снимает «последний удачный», вопрос, согласие заранее, «Остаться», без вопроса для устройства раздачи и единственного сервера); автосплит (D-45: `AutomaticDomesticRoutingTest`, `PolicyBuilderTest.autoModeEnablesDomesticSplit`, `XrayCompilerTest.automaticDomesticAddsCheckedRuRulesAfterUserRules`); личность сборки (D-47: `IdentityTest`); устройство раздачи (D-55: `RelayTest` — ссылка, хранение, вход SOCKS5, подключение только через устройство, отказ проверки здоровья через него — `RELAY_UPSTREAM_FAILED` (D-59); `XrayCompilerTest.relayDeviceCompilesToSocksWithPassword`); сопряжение по коду (D-56: `PairingTest` — один код на обоих экранах, отказ, подмена ключей, обязательство, порча входа); раздача туннеля (D-51: `ShareSettingsTest` — выключена по умолчанию, случайные порт и пароль, карантин; `TetherInterfacesTest` — что считается интерфейсом раздачи и когда переподключаться; `XrayCompilerTest.shareInboundsListenOnlyOnTetherAddressesWithAuth` — входы только на адресах раздачи, с паролем, и только для клиентов раздачи) |
| Интерфейс без Android | `app/src/test` | логика экранов (D-34): строки серверов и подписок, поиск и порядок по задержке, уровни задержки, значок сервера, трафик и срок подписки, длительность и скорость, источник конфигурации, состояние туннеля и счётчик скорости (`PresentationTest`, `TunnelStatusTest`, `TrafficMeterTest`); методы экранов не совпадают с методами View — иначе вызов из `apply` на View молча уходит в View (`ScreenNamesTest`) — тестами JVM, без устройства |
| Межмодульные | `tests/integration` | сквозные сценарии через `DPpassCore`: документ → активная конфигурация → подключение; подписка → атомарная активация; откат к last-known-good; отказ запуска кандидата; секреты нигде не всплывают |
| Корпус регрессий | `tests/regression` + `tests/data/` | файлы-примеры с ожиданиями (§2); эталоны компилятора Xray (§2, «Эталоны Xray») |
| Xray на хосте | `tools/xray` (шаг hostcheck «Xray») | эталоны принимает само ядро закреплённой версии (`xray run -test`), его решения маршрутизации совпадают с `RouteEvaluator` (D-24) |
| Мост Xray и JNI | `tools/xray/bridge`, `tests/integration/src/xrayJni` (шаг hostcheck «Xray: мост и JNI») | мост ядра в процессе (D-25): `go test` в обеих сборках, затем та же библиотека через JNI в JVM хоста — версия, проверка, один экземпляр, защитник сокетов из потоков Go и закрытие пути при его отказе, счётчики (§2, «Мост Xray и JNI») |
| Fuzz | `tests/fuzz` | на любом входе разбор возвращает `Outcome`, не бросает и укладывается во время (§4) |
| `cli` smoke | `smoke.cli` DP Verify (`tools/dpverify.toml`) | весь конвейер через оболочку JVM (15 сценариев): коды выхода, вывод, отсутствие секретов в выводе |
| Android | `:app:build`, `:app:lint`, `check_android_api.py`, `check_apk.py` | APK собирается вместе с библиотекой ядра `libdppassxray.so` (D-25); Lint без предупреждений; API модулей ядра ≤ minSdk 26; собранный APK — итоговый манифест, код только из утверждённых корней пакетов, нативный код — только библиотека ядра трёх ABI, выровненная по 16 КБ |
| Статические | `tools/dpv/dpv run static` (`tools/dpverify.toml`, D-50) | границы модулей, запрещённые API, секреты, синтетичность данных, корпус, ссылки, зависимости, манифест, формат, прогресс в README |
| На устройстве | `TODO.md`, «На устройстве» | то, что модель на хосте не покрывает (этап 3) |

Правила для всех тестов:

- **Детерминизм.** Время — `ManualClock`, ожидание — функция `pause`,
  двигающая часы; сна нет. Случайность — только с явным зерном.
- **Без сети.** Тесты не обращаются к сети: подписка «загружается» из
  памяти, пробы и здоровье — модель сети (§3).
- **Падающий тест не отключается.** Его чинят, а если поменялось
  решение — меняют тест вместе с решением (`CLAUDE.md`, «Чего не делать»).
- **Тест, который не запускается, — ошибка.** Метод `@Test`, который
  возвращает значение (`fun x() = runBlocking { … assertIs<…>(…) }`),
  JUnit не запускает. Предупреждения обнаружения тестов сделаны
  критичными (`junit.platform.discovery.issue.severity.critical`, в
  `build-logic`), и такой прогон падает. Тело теста должно кончаться
  выражением типа `Unit`.

## 2. Корпус регрессий

Каждый файл в `tests/data/` с ожиданием — отдельный динамический тест
`CorpusTest`. **Новый баг — новый файл корпуса**, а не правка кода без
следа. Соглашения проверяет `tools/hostcheck/check_fixtures.py`: у
каждого входа есть ожидание и наоборот, ключи и значения ожиданий —
только известные, коды — из `DiagCode`, данные — синтетические.
Корпус — вход задач тестов Gradle (`build-logic/src/main/kotlin/dppass.kotlin-library.gradle.kts`):
правка файла в `tests/data/` перезапускает тесты и без изменения кода.

### `configs/` и `dns/` — документы конфигурации

`ИМЯ.json` — документ, `ИМЯ.expect.json` — ожидание:

```json
{
  "load": { "outcome": "ok", "codes": ["RULE_SHADOWED"] },
  "activate": { "backend": "mock-limited", "outcome": "rejected", "codes": ["CAPABILITY_TRANSPORT_UNSUPPORTED"] }
}
```

- `load.outcome` — `ok` или `rejected`; `codes` должны найтись в дереве
  находок (с причинами). При `ok` любая находка серьёзнее INFO, не
  перечисленная в `codes`, — провал: неожиданное предупреждение тоже
  регрессия.
- `activate` (необязательно) — активация на фиктивном ядре: `backend` —
  `mock` (по умолчанию) или `mock-limited`, `outcome` — `activated` или
  `rejected`, `codes` — в дереве находок активации.
- `xray` — компиляция для Xray (обязательно, если `load.outcome` — `ok`):
  `outcome` — `compiled` (каждый профиль скомпилирован без находок
  сверх `codes`, результат совпал с эталоном) или `rejected` (хотя бы
  один профиль отвергнут), `codes` — в находках компиляции. `geodata`
  (необязательно) — оглавление набора геоданных в корпусе
  (`geodata/manifest.json`): коды и атрибуты сверяются с ним, как на
  устройстве (D-27); без него не сверяются, как на хосте.

Имя файла начинается с ожидаемого исхода: `valid-…`, `invalid-…`,
`warning-…`, `info-…`, `limited-backend-…` (ядро не умеет: фиктивное
`mock-limited` или Xray — `limited-backend-xray-…`).

### `subscriptions/` — тела подписок

`ИМЯ.txt` — тело как пришло, `ИМЯ.headers.json` (необязательно) —
заголовки ответа, `ИМЯ.expect.json`:
`{"outcome": "ready" | "failed", "profiles": N, "codes": [...]}`;
`profiles` — сколько серверов прошло проверку и фильтр ядра (`mock`).
`remnawave-*` — синтетическая копия формы ответа панели Remnawave
(`docs/research/REMNAWAVE_SUBSCRIPTIONS.md`): те же схемы, параметры и
заголовки, но значения выдуманные; заглушки при лимите устройств (D-33).

### `routing/` — решения маршрутизации

`ИМЯ.cases.json` ссылается на конфигурацию (`config`), задаёт таблицу
геоданных (`geo.geoip`) и случаи: запрос (`domain`, `ip`, `port`,
`protocol`, `package`) → `action` и `rule` (id правила или `null` для
действия по умолчанию). Ожидания сверяются с эталонным `RouteEvaluator`;
по тем же случаям сверяется Xray («Эталоны Xray» ниже).

### Эталоны Xray

Компилятор `XrayCompiler` (D-24) проверяется двумя половинами:

1. **`CorpusTest` — эталоны.** Каждая разбираемая конфигурация
   `configs/` и `dns/` с `xray.outcome = compiled` компилируется по
   профилю, с TUN (как на устройстве), и сравнивается с эталоном
   `tests/data/xray/<каталог>/<имя>/<профиль>.json` побайтно. Для
   каждого `routing/ИМЯ.cases.json` — эталон конфигурации
   `xray/routing/ИМЯ.config.json` и файл сверки
   `xray/routing/ИМЯ.probe.json`: запросы и ожидание — решение
   `RouteEvaluator` в тегах Xray (исходящий и `ruleTag` = id правила).
   Случаи, которые решает не ядро (приложение вне туннеля — уровень
   VpnService), записаны в `skipped` с причиной.
2. **Шаг hostcheck «Xray» (`tools/xray/check_xray.py`) — само ядро.**
   Собирает upstream `xray` и свой `dppass-xray-probe` из
   `tools/xray/go.mod` (версия — та, что в каталоге; суммы модулей — из
   `go.sum` и sum.golang.org), проверяет, что каждый эталон принимает
   `xray run -test`, и спрашивает маршрутизатор Xray о каждом случае
   `*.probe.json` (`Router.PickRoute` без запуска ядра и без сети).
   Геоданные — синтетические, из таблиц корпуса: код без таблицы пуст,
   как у `GeoResolver.None`.

`xray run -test` собирает конфигурацию, но не соединяется: то, что Xray
принял бы, но понял иначе, ловит не он, а отказ компилятора
(`XrayCompilerTest`) и сверка решений.

Намеренное изменение результата компилятора — перезапись эталонов и
обзор разницы в git:

```sh
./gradlew :tests:regression:test -Ddppass.golden.update=true
```

`check_fixtures.py` следит за составом: эталон на каждый профиль и
ничего лишнего, у отвергнутой компиляции эталонов нет, у каждого файла
случаев есть сверка с Xray. Без Go шаг «Xray» пропускается громко, в
`--full` — ошибка.

### Мост Xray и JNI

Ядро работает в процессе приложения через мост `tools/xray` (D-25);
проверяется он на хосте дважды — на Go и через JNI:

1. **`go test` моста** (`tools/xray/bridge`) в двух сборках: для APK и с
   тегом `dppass_testinbound`, где политика моста допускает тестовый
   вход `dokodemo-door` на loopback. Сквозные тесты гонят соединение
   «loopback → ядро → эхо-сервер»: защитник видит каждый исходящий сокет
   ядра, его отказ закрывает путь, счётчики считают трафик, после
   остановки вход освобождается. Код `geoip`/`geosite`, которого нет в
   наборе геоданных, — отказ проверки, а не условие, которое молча не
   выполняется (D-27). Вход раздачи (D-51) проходит, только если это
   SOCKS с тегом раздачи, паролем, частным IPv4 и портом от 1024
   (`TestPolicyAllowsOnlyAuthenticatedShareInbound`). Сопоставление с
   геоданными для объяснения решений (`GeoMatch`, D-27) отвечает так же,
   как маршрутизатор Xray с правилом на тот же код: домен, полное имя,
   подстрока, regexp, регистр имени, сочетание атрибутов, которого нет ни
   у одной записи, IPv4 и IPv6 (`TestGeoMatchAgreesWithRouter`); кода нет
   в наборе — отказ, как у проверки конфигурации, и после смены каталога
   тоже (`TestGeoMatchFollowsAssetDir`); набора нет — отказ договора, а
   не «такого кода нет» (`TestGeoMatchWithoutSetIsContractNotUnknownCode`).
2. **`XrayJniTest`** (`tests/integration/src/xrayJni`, задача
   `xrayJniTest`): тот же мост, собранный `tools/xray/native.py host`
   как `libdppassxray.so` для JVM хоста, загружается в JVM теста через
   `JniXrayRuntime`. Проверяется договор JNI: версия ядра равна
   `XrayBackend.VERSION`; эталон компилятора проходит полную проверку,
   битый JSON и чужой вход (SOCKS) — отказ `CONFIG`, а входы раздачи
   компилятора (D-51) с правилом-ограничителем — проходят; конфигурация с
   `geoip` без каталога геоданных — отказ (так ядро ведёт себя, если
   набор на устройстве не перенёсся, D-27); второй запуск — `RUNNING`, проверка при
   работающем ядре — неполная; TUN без защитника или без fd — `CONTRACT`;
   защитник вызывается из потоков Go, его отказ и исключение в нём
   закрывают путь, а не роняют JVM; счётчики и `XrayProxyEngine` поверх
   JNI; сопоставление с геоданными — по синтетическому набору
   (`XrayJniTest.geoMatchAnswersFromTheSet`) и отказ без набора, с
   отказом объяснения решения (`XrayJniTest.geoMatchWithoutSetIsRefused`).

Без библиотеки задача `xrayJniTest` падает с подсказкой, а не
пропускается; в `check` входит только компиляция этого набора. Запуск
вручную:

```sh
python3 tools/xray/native.py host
./gradlew :tests:integration:xrayJniTest -Pdppass.xray.lib=build/xray/host/libdppassxray.so
```

Библиотеку для APK (без тестового входа, три ABI, выравнивание 16 КБ)
собирает `native.py android`; она проверяется на устройстве (этап 2,
`TODO.md`, «На устройстве») и шагом «Android: APK» (там же — размер APK
одного ABI, D-28).

Проба здоровья (D-32) проверяется на хосте так же дважды:
- `go test` моста — проба через proxy и защитника в обход правил, к
  серверам DNS на loopback: UDP, TCP и DoH с TLS. Чужой корень — отказ
  TLS; чужой id и HTTP 403 — «не тот ответ»; молчание и закрытый порт —
  «ни байта»; ответа нет после рукопожатия — «данные не идут»;
- `XrayJniTest.dnsProbeGoesThroughProxyAndProtector` — проба через JNI.

Выбор сервера для пробы и коды её исходов проверяют `XrayHealthTest` и
`XrayProxyEngineTest`.

### Набор геоданных

Набор (D-27, D-31) собирает свой сборщик `tools/xray/geodata` из
закреплённых источников. Проверяется он в трёх местах:

1. **`go test` сборщика** — на синтетических данных: перевод диапазонов в
   подсети и вычитание (`TestRangesBecomeTheFewestAlignedPrefixes`),
   таблица `private` по самому узкому блоку реестра IANA
   (`TestPrivateFollowsTheNarrowestRegistryBlock`), строгий разбор DB-IP и
   dlc (`TestDbipRejectsWhatItCannotRead`, `TestDlcRejectsWhatItCannotRead`),
   `include` с фильтрами и аффилиации
   (`TestDlcResolvesIncludesFiltersAndAffiliations`), детерминизм
   (`TestBuildIsDeterministicAndManifestDescribesFiles`), приём набора
   ядром (`TestXrayAcceptsTheSet`), сочетания атрибутов в оглавлении —
   ровно те, по которым ядро находит имена
   (`TestManifestAttrSetsAreWhatXrayMatches`).
2. **Эталон оглавления** `geodata/manifest.json` в корпусе. Go-тест
   `TestManifestMatchesGolden` сверяет с ним оглавление синтетического
   набора, а Kotlin-тест `GeodataTest.builderManifestParses` его
   разбирает: договор «сборщик → приложение» не разойдётся молча.
   Обновить эталон: `DPPASS_GOLDEN_UPDATE=1 go test ./geodata` в
   `tools/xray`.
3. **Шаг hostcheck «Xray: геоданные»** (`geodata.py --test`): настоящий
   набор из закреплённых источников, суммы источников сверены с
   PROVENANCE, ядро Xray загружает каждый код набора.

Набор в APK проверяет `check_apk.py` (шаг «Android: APK»): файлы — ровно
по оглавлению, `.dat` сжаты, SHA-256 и размеры совпадают, источники — из
каталога, атрибуция DB-IP на месте, оглавление побайтно совпадает с
набором шага «Xray: геоданные». Коды конфигурации компилятор сверяет с
оглавлением установленного набора
(`XrayCompilerTest.geoCodesAreCheckedAgainstTheInstalledSet`; в корпусе —
`configs/limited-backend-xray-geosite-attrs` с `xray.geodata`).

Объяснение решений (`ProxyEngine.explain`, D-09) у Xray идёт на наборе
ядра: geosite и geoip спрашиваются у моста, правило без геоданных мост не
трогает, а отказ моста — отказ объяснения, а не «условие не сработало»
(`XrayProxyEngineTest.explanationAsksTheCoreGeodata`,
`XrayProxyEngineTest.explanationIsRefusedWhenGeodataDoesNotAnswer`).

Перенос набора на устройстве (`GeodataInstaller`) проверяет `GeodataTest`:
файл, не совпавший с оглавлением, не ставится; прерванный перенос не
оставляет набора; тот же набор второй раз не переносится; новый набор
заменяет старый; имена файлов с путём отвергаются.

### `network/conditions.json` — модель сети

Для каждого условия модели (§3) — ожидаемый класс сети, доступности
(`dns`, `udp`, `tls`), исключённые кандидаты, первый класс в плане,
единственный кандидат, подключится ли и с каким вердиктом.
`check_fixtures.py` требует строку для **каждого** условия модели.

### Данные корпуса

Только синтетические: IP из документационных диапазонов (RFC 5737,
RFC 3849, RFC 2544) и частных сетей, домены `example.com/.net/.org`,
`.example`, `.test`, `.invalid` (исключение — `example.ru` как образец
«отечественного» домена; трафик к нему не отправляется), UUID вида
`00000000-0000-…`, пароли вида `test-password-N`. Настоящий сервер или
ключ в корпусе — находка `data.synthetic` и `security.secrets`.

## 3. Модель сети

`network.simulation.SimulatedNetwork` — **синтетические классы**
ограничений из `docs/research/RUSSIA_NETWORK_RESTRICTIONS.md`, а не
снимки операторов. Модель отвечает на пробы (`Prober`) и на вопрос
«что увидит соединение кандидата данного класса»
(`candidatePath`: данные идут, «подключено, но пусто», отказ).

| Условие | Пробы | Кандидаты |
|---|---|---|
| `NORMAL` | всё проходит | всё работает |
| `DNS_BLOCKED` | зарубежный DNS подменён | работают |
| `DNS_DEGRADED` | зарубежный DNS не отвечает | работают |
| `IP_BLOCKED` | всё проходит | заблокированные адреса не отвечают |
| `TCP_REACHABLE_UDP_BLOCKED` | UDP не проходит | UDP/QUIC не работает |
| `TLS_DEGRADED` | зарубежный TLS сброшен, крупная передача стоит | TCP-поток «подключено, но пусто» |
| `HIGH_LATENCY` | задержка 2,5 с | работают |
| `PACKET_LOSS` | зарубежный TLS — тайм-аут, крупная передача стоит | работает только UDP/QUIC |
| `CAPTIVE_PORTAL` | HTTP перенаправлен | ничего |
| `ALLOWLIST_LIKE` | отечественное доступно, зарубежное — нет | только отмеченные `allowlist_reachable` |
| `FULL_ENDPOINT_BLOCK` | всё проходит | ни один сервер не отвечает |
| `OFFLINE` | ничего | ничего |

Модель — инструмент тестов и `cli`; в приложение она не попадает
(`code.forbidden`, правило `simulation-import`). Новое условие — строка в этой таблице, в
`conditions.json` и в `NetworkClassifierTest`.

Пробы на сокетах (D-60) проверяются на хосте без внешней сети:
`SocketProberTest` — локальные серверы TCP, UDP и HTTP вместо ориентиров
(успех, отказ, тайм-аут, подмена DNS, «замерзание» передачи, ответ не 2xx,
ответ и молчание по UDP); `QuicInitialTest` — ключи и маска заголовка по
векторам RFC 9001 (приложение A), снятие защиты пакета так, как это делает
сервер, и отличие ответа на своё соединение от чужого пакета. ClientHello
пакета сверен 17 октября 2026 разбором `crypto/tls` (QUIC) Go 1.24: SNI, ALPN
`h3`, параметры транспорта, ответ ServerHello. Совпадение классификации на
телефоне с моделью — критерий выхода этапа 3 (`TODO.md`).

Наблюдения с телефона, на которых классификатор ошибся, — файлы
`tests/data/network/observations/*.json` (исходы проб без адресов, тип сети
и ожидаемый класс); их сверяет `CorpusTest.networkObservations`, формат —
`check_fixtures.py`. Первый — `skipped-foreign-probes.json` (17 октября 2026:
пропуски бюджета давали «все пробы прошли»).

Замер через туннель (D-61) — Go-тесты моста через proxy ядра к локальному
HTTPS-серверу с заданным объёмом ответа (`TestSpeedTest*`), `XraySpeedTest`
(расчёт и договор ответа) и `XrayJniTest.speedTestGoesThroughProxyAndKeepsTheContract`.

## 4. Fuzz

`tests/fuzz/FuzzTest` — мутационный fuzz с фиксированным зерном:
воспроизводим и идёт в каждом прогоне hostcheck. Семена — файлы
корпуса; мутации — вставка «опасных» токенов (глубокая вложенность,
повтор ключа, `\u0000`, BOM, суррогаты, `%zz`, длинные строки),
удаление, повтор фрагментов, обрезка. Свойство: разбор документа,
ссылки и тела подписки не бросает исключений, отказ содержит хотя бы
одну ошибку, один вход обрабатывается быстрее 2 с. Плюс вырожденные
случаи: огромный и глубокий документ отвергаются сразу, 4097 правил —
`LIMIT_EXCEEDED` за отведённое время.

Параметры: `-Ddppass.fuzz.iterations=N` (по умолчанию 1500),
`-Ddppass.fuzz.seed=S` (по умолчанию 20261004). Глубокий прогон:

```sh
./gradlew :tests:fuzz:test -Ddppass.fuzz.iterations=200000 -Ddppass.fuzz.seed=1
```

Параметры пробрасывает в JVM тестов
`build-logic/src/main/kotlin/dppass.kotlin-library.gradle.kts`; смена
значения — новый вход задачи, тест перезапускается.

**Найденный сбой становится файлом корпуса** (`tests/data/`), а не
только исправлением.

## 5. Что тесты не покрывают

- Ядро в работе: Xray на хосте собирает конфигурацию и решает
  маршрутизацию, но не соединяется; подключение через TUN — на
  устройстве (`docs/direction/ROADMAP/02-xray-backend.md`).
- Настоящая сеть — этап 3.
- Ограничения Android, которых нет на хосте: например, запрет netlink
  для приложений с Android 11 (вход TUN Xray без имени не собирался —
  найдено по журналу устройства, D-26). Найденное закрепляется тестом
  на хосте (`XrayCompilerTest.tunInboundIsNamedSoXrayDoesNotEnumerateInterfaces`).
- Android на устройстве: Keystore, `VpnService`, `FLAG_SECURE`,
  резервные копии, буфер обмена и обработчик падений журнала
  устройства — `TODO.md`, «На устройстве».
- Производительность на устройстве — `docs/PERFORMANCE_BUDGET.md`
  (на хосте — только ориентиры).
