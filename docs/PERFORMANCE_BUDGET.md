# Бюджет производительности DPpass

Срез на **4 октября 2026** (конец этапа 1). Что DPpass ограничивает
сам, сколько это стоит на хосте и что будет измерено на устройстве.

## 1. Принцип

- **Пределы — в коде, а не в надежде.** Всё, что приходит извне
  (документ, подписка, правила), ограничено до разбора; превышение —
  отказ с кодом (`DOCUMENT_TOO_LARGE`, `DOCUMENT_TOO_DEEP`,
  `SUBSCRIPTION_TOO_LARGE`, `LIMIT_EXCEEDED`), а не долгая работа (D-05, угроза T6 в
  `docs/SECURITY_MODEL.md`).
- **Хост — ориентир, не порог.** Время на хосте и на телефоне
  различается в разы; замеры хоста (§3) показывают порядок величин и
  ловят регрессии «в разы». Пороги — на устройстве (§4, этап 3 в
  `docs/direction/ROADMAP/03-device.md`).
- **Ориентиры меняются по замерам**, а не наугад (D-15): новое значение
  предела — вместе с замером, который его обосновывает.

## 2. Пределы в коде

| Что | Предел | Где | Тест |
|---|---|---|---|
| Документ конфигурации | 1 МиБ | `ConfigLimits.maxBytes` | `ConfigLoaderTest`, `FuzzTest.hugeAndDeepDocumentsAreRejectedQuickly` (`DOCUMENT_TOO_LARGE`) |
| Вложенность JSON документа | 32 | `ConfigLimits.maxDepth`; разбор останавливается, не дойдя до дна | `JsonTest.depthIsBoundedWithoutStackOverflow`, `FuzzTest.hugeAndDeepDocumentsAreRejectedQuickly` (`DOCUMENT_TOO_DEEP`) |
| Профили в документе | 512 | `ConfigLimits.maxProfiles` | `ConfigLimitsTest.profilesUpToLimitPassOneMoreIsRejected` |
| Правила маршрутизации | 4096 | `ConfigLimits.maxRules` | `FuzzTest.ruleLimitsAndDuplicatesStayFast` (4097 правил — `LIMIT_EXCEEDED` быстрее 2 с) |
| Значения во всех правилах | 100 000 | `ConfigLimits.maxRuleValues` | `ConfigLimitsTest.ruleValuesUpToLimitPassOneMoreIsRejected` |
| Тело подписки | 2 МиБ | `FetchPolicy.maxBytes` | `SubscriptionUpdaterTest` (`SUBSCRIPTION_TOO_LARGE`) |
| Записи подписки | 1000; остальные не читаются (`SUBSCRIPTION_ENTRY_SKIPPED`) | `FetchPolicy.maxEntries` | `PayloadLimitsTest.entriesUpToLimitAreReadTheRestAreSkippedLoudly` |
| Загрузка подписки | 20 с | `FetchPolicy.timeoutMillis` (соединение и чтение; в `HttpsSubscriptionFetcher` — от 1 до 120 с) | `HttpsSubscriptionFetcherTest.timeoutIsSetForConnectAndReadWithinBounds` (значение, границы и отказ по сроку; сам срок отсчитывает JDK) |
| Подписок в приложении | 64; адрес — 2048 символов, имя — 64 | `SubscriptionService.MAX_SUBSCRIPTIONS`, `MAX_URL`, `MAX_NAME` | `LimitsTest.subscriptionsUpTo64`, `LimitsTest.subscriptionUrlUpTo2048NameUpTo64` |
| Обновление по расписанию | задание раз в час; подписка — по своему интервалу (по умолчанию 12 ч); после отказа — не раньше чем через 30 мин; только активная | `SubscriptionJobService`, `UpdateSchedule` (D-39) | `UpdateScheduleTest.intervalsFailuresAndOff` |
| Импорт (буфер, файл, «Поделиться») | 1 МиБ | `ImportClassifier.MAX_BYTES` | `ImportClassifierTest.plainHttpAndOversizedTextAreRefusedWithReason` |
| Приложения в политике | 1000 | `UserPolicy.MAX_APPS` | `LimitsTest.policyAppsUpTo1000` |
| Проверка задержки | по одному серверу, пауза 150 мс, тайм-аут 3 с, не больше 128 за прогон | `LatencyBook` (D-41) | `LatencyBookTest.measuresTcpOneByOneAndSkipsUdp` |
| Обновление уведомления туннеля | раз в 2 с и только при включённом экране | `DPpassVpnService` (D-40) | нет (на устройстве) |
| Опрос интерфейсов раздачи | раз в 5 с, только пока раздача включена и туннель поднят; новый интерфейс — после двух опросов подряд | `DPpassVpnService.SHARE_POLL_MILLIS`, `TetherInterfaces.shouldReconnect` (D-51) | `TetherInterfacesTest.goneInterfaceReconnectsAtOnceNewOneAfterTwoPolls` (решение; период — на устройстве) |
| История активаций | 32 записи | `ActivationStore` | `LimitsTest.activationHistoryKeepsLast32` |
| Пробы сети | 1 на ориентир за 1,5 с; не больше 12 за 60 с; бюджет один на процесс (две проверки подряд — пропуски, а не залп) | `ProbeBudget`, `NetworkCheck` (D-60) | `ProbeBudgetTest` (механизм — на своих параметрах) |
| Одна проба на сокетах | соединение и чтение — 5 с; крупная передача — 64 КБ, прошло при 32 КБ, не дольше 10 с; QUIC — одна датаграмма 1200 байт | `SocketProber`, `QuicInitial` (D-60) | `SocketProberTest` (механизм — на сроках 0,7 и 1,5 с) |
| Замер через туннель | 10 малых запросов; загрузка не больше 25 МБ и не дольше 8 с; весь замер — не дольше 25 с; один за раз, только по кнопке | `XraySpeed` (D-61) | `TestSpeedTestStopsAtTimeLimit` (срок загрузки), `XraySpeedTest` (итог) |
| Кандидаты за подключение | 4, пауза 2 с между попытками | `ConnectionPolicy` | `CandidatePlannerTest`, `OrchestratorTest` |
| Проверка здоровья | 10 с | `ConnectionPolicy.healthTimeoutMillis` | `LimitsTest.healthCheckThatNeverAnswersFailsTheAttemptAtTimeout` (значение; механизм — на сроке 50 мс) |
| Пауза кандидата после отказа | 30 с × 2ⁿ⁻¹, не больше 30 мин | `ConnectionPolicy` | `CandidatePlannerTest.backoffExcludesUntilItExpires` |
| Один вход fuzz | < 2 с | `FuzzTest` | каждый прогон hostcheck |

Предел без теста — долг (`TODO.md`): сам предел в коде есть, но
регрессия в нём (снятая проверка, неверное сравнение) пройдёт незамеченной.

Смена предела — правка этой таблицы в том же изменении; предел
формата документа (размер, глубина, число правил) — ещё и
`docs/CONFIG_FORMAT.md`.

## 3. Замеры на хосте

Команда — `dppass-cli bench --rules N` (`cli/`): синтетический документ
с N правилами `domain_suffix` (по два значения), один профиль Trojan+TLS;
разбор с проверкой, компиляция фиктивным ядром, 20 000 решений
`RouteEvaluator` на именах, не совпадающих ни с одним правилом (худший
случай: перебираются все правила). Три прогона подряд после прогрева JIT.

Хост: Intel Xeon 2,8 ГГц, 4 ядра, OpenJDK 21.0.11, Linux; 4 октября 2026.

| Правил | Документ | Разбор + нормализация + проверка | Компиляция (mock) | Решение маршрутизации |
|---|---|---|---|---|
| 200 | 17 КиБ | 9–10 мс | 15–16 мс | 7,1–7,2 мкс |
| 2000 | 173 КиБ | 110–164 мс | 33–66 мс | 117–125 мкс |
| 4096 (предел) | 358 КиБ | 470–631 мс | 52–53 мс | 248–265 мкс |

Что из этого следует:

- **Решение маршрутизации линейно по числу правил** (~60 нс на правило):
  `RouteEvaluator` перебирает правила по порядку. Он объясняет решения
  и сверяет компиляторы ядер, трафик маршрутизирует ядро (`docs/ARCHITECTURE.md`, §5),
  поэтому для его задач этого достаточно; если понадобится массово —
  индекс по суффиксам (`TODO.md`).
- **Разбор документа на пределе — полсекунды на хосте**; на телефоне
  ожидается кратно дольше. Разбор и активация не идут в главном потоке
  интерфейса (этап 4); порог — на устройстве.
- Повтор замера — та же команда; результат записывается сюда с датой и
  машиной, старая строка заменяется (история — в git).

## 4. На устройстве

Пороги, которые ставятся на этапе 3 по замерам на устройствах (дата,
модель, версия Android); до этого — не обещаются.

| Метрика | Почему важна | Когда |
|---|---|---|
| Время от «подключить» до первых данных | заметно пользователю; зависит от плана кандидатов и проверки здоровья | этап 3 |
| Память процесса с туннелем | Go-ядро плюс JVM; процесс сервиса убивается системой при нехватке | этап 2–3 |
| Батарея в простое с туннелем | постоянная работа сервиса | этап 3 |
| Разбор и активация документа на пределе правил | §3: полсекунды на хосте | этап 3 |
| Размер APK по ABI | нативное ядро — основная часть размера. Замер 4 октября 2026 (хост, `check_apk.py` на debug APK): `libdppassxray.so` без сжатия — arm64-v8a 34,3 МиБ, armeabi-v7a 33,1 МиБ, x86_64 36,6 МиБ; APK с тремя ABI — 105,7 МиБ; без библиотек других ABI — arm64-v8a 36,0, armeabi-v7a 34,9, x86_64 38,3 МиБ. Выпуск — APK на ABI (D-28). Набор геоданных (D-27) в APK — замер 5 октября 2026: 24,5 МиБ без сжатия, в APK — около 5,9 МиБ на каждый APK; APK одного ABI с ним — arm64-v8a 41,9, armeabi-v7a 40,8, x86_64 44,2 МиБ. **Предел APK одного ABI — 46 МиБ** (замер плюс запас; до набора был 40; `check_apk.py`, `ABI_APK_BUDGET_MIB`) | этап 2 — замер и предел; APK по ABI — этап 5 |
| Холодный запуск приложения | расшифровка ключа хранилища, чтение состояния активации | этап 3 |
