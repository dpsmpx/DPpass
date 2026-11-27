# Инвентаризация локального DPI-движка 0.9

Дата: 24 ноября 2026. Предварительный результат A2, не завершённый
аудит каждого файла и не перечень уже реализованных функций.

## Проверенные источники

- [ByeDPI 0.17.3, README](https://github.com/hufrea/byedpi/blob/7efde1b1296eaaa187b70e951894dde17527489c/README.md),
  [desync.c](https://github.com/hufrea/byedpi/blob/7efde1b1296eaaa187b70e951894dde17527489c/desync.c).
- [Zapret2 v1.0.7, zapret-antidpi.lua](https://github.com/bol-van/zapret2/blob/v1.0.7/lua/zapret-antidpi.lua),
  [zapret-auto.lua](https://github.com/bol-van/zapret2/blob/v1.0.7/lua/zapret-auto.lua),
  [zapret-obfs.lua](https://github.com/bol-van/zapret2/blob/v1.0.7/lua/zapret-obfs.lua).
- DPpass RC6 / cd08ad620a3e49163f95dc6af1acc7cc01bc19cd:
  tools/xray/zapret2, tools/xray/bridge, Android ROOT/ByeDPI runtime.
- A1 / fed754972782fa0f56e3dc58c1e6c759a51eddee:
  tools/xray/localdpi/catalog.go.

Лицензии закреплённых upstream версий — MIT, проверены отдельно.
Перенос исходников ещё не выполнен.

## Карта семейств

| Семейство | ByeDPI | Zapret2 | DPpass сейчас / решение |
|---|---|---|---|
| Неизменённое соединение | baseline | обычная передача | pass; общий контроль |
| Разбиение потока | split | multisplit, tcpseg | часть методов Go; общий контракт, полная эквивалентность не доказана |
| Перестановка частей | disorder | multidisorder, legacy | частичная сокетная реализация; отдельные пакетные возможности |
| Подставные данные | fake | fake, hostfakesplit, fakedsplit, fakeddisorder | часть методов Go; не считать эквивалентными без тестов |
| TLS записи | tlsrec, tlsminor | tls_client_hello_clone и другие TLS операции | tlsrec-split реализован; различия проверить |
| HTTP форматирование | mod-http | http_domcase, http_hostcase, http_methodeol, http_unixeol | отдельное семейство; не заявлять полную поддержку |
| Срочные данные TCP | oob, disoob | oob | отдельный кандидат для аудита сокетных возможностей |
| UDP | udp-fake, проксирование UDP | fake, udplen, dht_dn | ограниченные QUIC-кандидаты DPpass; UDP не равен QUIC |
| Параметры TCP/пакетов | md5sig, socket options | synack, syndata, wsize, wssize, rst, pktmod, drop, send | проверять каждую возможность ОС; пакетные операции ROOT отдельно |
| Иные преобразования | нет прямого соответствия в просмотренном описании | wgobfs, ippxor, udp2icmp, synhide | отдельная оценка совместимости; не включать автоматически |
| Отбор соединений | proto, hosts, ipset, pf, round | condition, per_instance_condition, stopif | общие правила области действия, не отдельные движки |
| Адаптация | auto, auto-mode, cache, timeout | standard_failure_detector, standard_success_detector, circular | общий контроллер, не два независимых алгоритма; отделить факт от гипотезы |

Сопоставление по названиям и описаниям не означает, что алгоритмы
имеют одинаковые входы, выходы или сетевое поведение. В частности
пакетный движок Zapret2 и сокетный движок ByeDPI могут иметь разные
границы наблюдения и права. Не добавлять в AUTO метод, который
не поддерживается фактическим исполнителем.

## Правила переноса

- Не импортировать CLI, конфигурационные парсеры и отдельные циклы
  управления соединениями, если они дублируют DPpass; отделять
  собственно метод от жизненного цикла.
- Для каждого кандидата: точный upstream файл/commit, лицензия и
  зависимость, входы и выходы, ограничения, допустимый исполнитель,
  тесты на локальных fixtures и сравнение с неизменённым upstream.
- Сохранять совместимость протоколов и неизменность полезных данных;
  не смешивать несовместимые преобразования. Отдельные проверки
  на отказ, отмену, смену сети, очистку состояния и ограничение ресурсов.
- Никакой автоматической активации новых методов до выполнения
  критериев A3–A6. Не изменять текущий RC6 и VPN подписки.
- Перед удалением исходных бинарников проверять фактическое поведение
  Android ROOT/VpnService и обновление поверх подписанного APK.

## Следующие незакрытые части A2

- Полный просмотр нативного nfqws2 и Lua-библиотек, ByeDPI headers,
  proxy/event loop и платформенных веток; происхождение каждого файла.
- Матрица доступности по ОС и привилегиям, включая Android kernels.
- Разделение точных эквивалентов, частичных аналогов и уникальных методов
  на основании тестов, а не совпадения названий.
- Тестовые эталоны и окончательный выбор первых переносимых модулей.

## Первый импорт A4

`packets.c` и `packets.h` закреплённого ByeDPI 0.17.3 перенесены
в неизменном виде, с полным MIT LICENSE и точными blob SHA-1
(`tools/localdpi/vendor/byedpi/README.md`). Зависимости просмотрены:
стандартная библиотека C, системные заголовки POSIX/Winsock.
Хостовые fixtures проверяют ограниченный набор распознавания/разбора
HTTP и TLS. Это не полное сопоставление алгоритмов и не аудит безопасности;
подключение к реальному трафику запрещено до проверки границ и fuzzing.

## A2 — границы нативных компонентов Zapret2

Просмотрены заголовки закреплённого v1.0.7 (tree 038c97e5819df10f8e8c22a2f1fffe57f2f7379b), Makefile и начало checksum.c; ByeDPI proxy.h/conev.h. Это карта зависимостей, не завершённый построчный аудит.

| Модуль | Связи и решение |
|---|---|
| nfq2/protocol.h | helpers.h; большой набор протоколов и позиционных маркеров. Отдельный кандидат после проверки реализации protocol.c и зависимостей. |
| nfq2/desync.h | darkmagic.h, IP/TCP структуры; интерфейс пакетного исполнителя, не эквивалент VpnService socket. |
| nfq2/conntrack.h | protocol, darkmagic, packet_queue, uthash, ограниченное reassembly. Не переносить весь conntrack в socket path. |
| nfq2/lua.h | Lua/LuaJIT, pools, conntrack, darkmagic. Не переносить как независимый алгоритм. |
| nfq2/Makefile | Linux/Android: zlib, netfilter_queue, nfnetlink, mnl, libm, Lua/LuaJIT; Android также liblog. Windows использует WinDivert; лицензии и происхождение зависимостей отдельно. |
| nfq2/checksum.c | Комментарий в do_csum указывает Linux source code. Не импортировать до установления точного происхождения/лицензии; общий MIT проекта не решает этот вопрос. |
| ByeDPI proxy.h / conev.h | SOCKS, event loop, epoll/poll/WSAPoll, управление fd и буферами. Не дублировать существующий Xray lifecycle; отделять методы от транспорта. |

ROOT остаётся отдельной границей привилегий. Проверка согласия не доказывает доступность NFQUEUE, raw socket, IPv6 NAT или разрешение SELinux. До регистрации ROOT возможностей нужны отдельные runtime probes и физические испытания. Импорт новых файлов Zapret2 этим шагом не выполнялся.

## A2/A4 — решение по legacy HTTP и native recognition

Повторно просмотрены parse_http и mod_http в неизменном packets.c (ByeDPI 7efde1b1296eaaa187b70e951894dde17527489c). parse_http ищет Host в пределах всего переданного буфера, имеет обратные проходы по whitespace/digits без явной нижней границы; mod_http наследует эти предположения и выполняет in-place правку. Не экспортировать их для произвольного трафика. Отдельный проектный шаг должен определить строгую семантику допустимых HTTP преобразований и тесты, а не просто открыть upstream функцию. Нативные is_http/is_tls_chello доступны в tagged Go только как ограниченные read-only hints; текущий строгий Go parser остаётся authority. Сравнение malformed fixtures демонстрирует, что совпадение названия протокола не означает эквивалентность распознавателей. Новый upstream метод не активирован.

## A4/A5 — первый самостоятельный HTTP operation

В общей Go-библиотеке реализован изолированный семантически сохраняющий вариант изменения регистра имени Host, соответствующий узкому семейству ByeDPI mod-http / Zapret2 http_hostcase. Это собственная реализация с общим строгим parser, не перенос legacy mod_http. Проверяется равная длина, те же field offsets и полное совпадение всех байтов вне четырёх букв имени поля. Значение Host, URI, заголовки, тело не меняются. В AUTO, DPTS и рабочие executors операция ещё не зарегистрирована; требуется отдельное проектирование action contract и физическая проверка. Не заявляется эквивалентность всего upstream семейства.

## A4/A5 — HTTP operation connected to executor

The previously isolated HTTPHostNameCase function is wired through the shared planner and real protected TCP adapter as an explicitly request-owned internal diagnostic operation (`http-hostcase`). It is not registered for AUTO, neural learning, TLS/QUIC, or the current user-facing DPTS grammar. The existing HTTP methods now receive bounded fragmented first headers. Exact wire validation and loopback regression cases are added; upstream-wide equivalence and physical acceptance remain open.

## A5 — portable multisplit subset

Reviewed pinned Zapret2 `lua/zapret-antidpi.lua` `multisplit`. Original resolves arbitrary markers and performs rawsend with replay/drop and optional sequence overlap. DPpass's independent restricted socket analogue uses two validated positions in one complete TLS ClientHello and ordered TCP writes; it preserves the stream and is exposed only through DPTS diagnostics. Raw packet behavior and equivalence are not claimed. No source imported in this step.

## A4 — limited upstream TLS name-parser comparison

The pinned ByeDPI `parse_tls` from the already imported `packets.c` is now called by a narrow read-only comparison ABI. It receives only the bounded first complete ClientHello; the C result is equality with the existing Go range, never a new host or offset. No C pointer or name is exported. Tagged diagnostic TLS-record encoding checks agreement when the Go parser finds a name; disagreement keeps the existing portable encoding. The production selector, ordinary builds, and the upstream HTTP parser are unchanged. This integrates one existing upstream function, not a new DPI strategy or proof of equivalence. CI and physical tests pending.

## A4 — native MH_HMIX on fixed HTTP fixture

A restricted ABI now executes pinned ByeDPI mod_http with MH_HMIX on the exact existing local POST fixture only. No arbitrary input reaches the unsafe legacy parser. Independent byte-exact Go reference expects hOsT on the fixture, replacing the previous diagnostic spelling hOSt. The tagged in-process diagnostic planner uses the native result when available; general HTTP, ordinary builds and selected Alpine IPC retain the portable operation. No claim of general mod_http support or DPI effectiveness.

## A4 — bounded HTTP authority adapter

The fixed-only native MH_HMIX fixture has been replaced by a bounded synthetic header adapter for eligible HTTP/1.x requests. The original request is never passed to legacy parse_http/mod_http; the common Go parser remains authoritative, and all bytes except the four field-name bytes are preserved. Native admission is narrower than the portable parser, so ports and literals retain the existing portable result. This is not the complete upstream HTTP mutation family; no production or AUTO admission is added.
