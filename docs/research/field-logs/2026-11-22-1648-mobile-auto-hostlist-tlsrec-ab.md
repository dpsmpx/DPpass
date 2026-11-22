# Полевой журнал: мобильная сеть, AUTO, 7-доменный hostlist и tlsrec-split

- **Исходное время:** 22.11.2026, 16:48:45–16:51:46 UTC (время `Z` из журнала).
- **Источник:** пользовательский журнал DPpass, сохранён дословно в разделе ниже.
- **Среда:** Android API 35, arm64-v8a, DPpass 0.7.54-dev, Xray 26.9.30, Alpine/PRoot.
- **Статус:** отрицательный прикладной результат: пользователь подтвердил, что YouTube не загрузил даже текст, хотя приложение было открыто после включения стратегий. Четыре успешных старта Alpine/TUN не означают успех YouTube (`content_verified=false`).
- **Изменения:** только документирование; ни настройки, ни код транспортных стратегий не менялись.

## Исходный журнал

```text
=== DPpass — журнал ===

=== Текущий сеанс ===
2026-11-22T16:48:45.296Z INFO app session_start version=0.7.54-dev api=35 abis=arm64-v8a,armeabi-v7a,armeabi debuggable=true
2026-11-22T16:48:45.725Z INFO app activity_create
2026-11-22T16:48:46.208Z INFO app geodata_ready set=dlc 63777333b7dd, DB-IP 2026-10 installed_now=true
2026-11-22T16:48:46.341Z INFO app engine_loaded backend=xray version=26.9.30
2026-11-22T16:48:46.369Z INFO core diagnostic code=ACTIVATION_REJECTED message=активация выполняется: восстановление отложено
2026-11-22T16:48:56.290Z INFO app service_start by=app
2026-11-22T16:48:56.569Z INFO core zapret2_alpine_start status=initializing
2026-11-22T16:48:57.774Z INFO app work_finished reason=activity_stop
2026-11-22T16:48:58.635Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T16:48:58.636Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T16:48:58.636Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T16:48:58.641Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T16:48:58.651Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T16:48:59.068Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T16:48:59.214Z INFO app underlying_network state=available type=MOBILE
2026-11-22T16:49:12.138Z INFO core zapret2_hostlist_set n=7
2026-11-22T16:49:12.427Z INFO app service_reconnect by=user
2026-11-22T16:49:12.435Z INFO core zapret2_transfer_final duration_ms=13266 up_bytes=94224 down_bytes=29974 applied_delta=5 skipped_delta=3 applied_total=7 skipped_total=6
2026-11-22T16:49:13.571Z INFO core zapret2_alpine_start status=initializing
2026-11-22T16:49:13.634Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T16:49:13.635Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T16:49:13.635Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T16:49:13.635Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T16:49:13.642Z INFO core serverless rest=direct dns=doh apps=all n=7 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T16:49:13.880Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T16:49:13.902Z INFO app underlying_network state=available type=MOBILE
2026-11-22T16:49:19.507Z INFO app work_finished reason=activity_stop
2026-11-22T16:49:35.915Z INFO app service_reconnect by=user
2026-11-22T16:49:35.926Z INFO core zapret2_transfer_final duration_ms=22034 up_bytes=262693 down_bytes=73492 applied_delta=16 skipped_delta=3 applied_total=25 skipped_total=9
2026-11-22T16:49:37.090Z INFO core zapret2_alpine_start status=initializing
2026-11-22T16:49:37.206Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T16:49:37.208Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T16:49:37.211Z INFO core <redacted> all_tcp=false selected=0 quic_trials_enabled=false
2026-11-22T16:49:37.213Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T16:49:37.266Z INFO core serverless rest=direct dns=doh apps=all n=7 local_desync=tlsrec-split quic_force_tcp=true https_unmatched=true
2026-11-22T16:49:37.663Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T16:49:37.694Z INFO app underlying_network state=available type=MOBILE
2026-11-22T16:49:38.071Z INFO app work_finished reason=activity_stop
2026-11-22T16:49:43.995Z INFO app service_reconnect by=user
2026-11-22T16:49:44.003Z INFO core zapret2_transfer_final duration_ms=6318 up_bytes=47744 down_bytes=7363 applied_delta=3 skipped_delta=0 applied_total=29 skipped_total=9
2026-11-22T16:49:45.262Z INFO core zapret2_alpine_start status=initializing
2026-11-22T16:49:45.376Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T16:49:45.376Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T16:49:45.378Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T16:49:45.378Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T16:49:45.386Z INFO core serverless rest=direct dns=doh apps=all n=7 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T16:49:45.670Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T16:49:45.717Z INFO app underlying_network state=available type=MOBILE
2026-11-22T16:49:46.077Z INFO app work_finished reason=activity_stop
2026-11-22T16:50:15.148Z INFO core zapret2_transfer_window up_bytes=156590 down_bytes=15697 applied_delta=12 skipped_delta=4 applied_total=42 skipped_total=13
2026-11-22T16:50:45.600Z INFO core zapret2_transfer_window up_bytes=263711 down_bytes=192256 applied_delta=21 skipped_delta=5 applied_total=63 skipped_total=18
2026-11-22T16:51:15.857Z INFO core zapret2_transfer_window up_bytes=431189 down_bytes=196549 applied_delta=38 skipped_delta=4 applied_total=101 skipped_total=22
2026-11-22T16:51:46.301Z INFO core zapret2_transfer_window up_bytes=218781 down_bytes=50258 applied_delta=9 skipped_delta=1 applied_total=110 skipped_total=23
```

## Подтверждённый пользователем результат испытания

**Уточнение автора после просмотра журнала:** YouTube был открыт уже после включения экспериментальных стратегий, но **вообще ничего не загрузилось — даже текст главной ленты**. Следовательно, результат прикладного испытания YouTube — **FAIL / содержание не получено**, несмотря на `connected`, ненулевой downstream и `applied_delta`. Счётчики фиксируют сетевую активность, а не работоспособность конкретного приложения. Нельзя приписывать трафик YouTube или объявлять пригодную стратегию по этому сеансу.

Уточнение относится к описанному сеансу с включёнными стратегиями; точно установить результат каждого из четырёх кратких A/B-подключений по отдельности из реплики нельзя. Ни одну стратегию не следует считать подтверждённой для YouTube.

**Диагностические гипотезы, пока не причины:** DoH не разрешает нужные домены; IP/CDN недоступен или действует белый список оператора; QUIC/TCP handshake срывается; Xray/маршрутизация теряет нужный поток; автооценка ошибочно считает фоновый трафик успехом. Для локального десинхронизатора критично разделять DNS, TCP connect, TLS handshake, первый HTTPS-ответ и последующий медиатрафик. Без этих наблюдений изменение очередности стратегий — неподтверждённая догадка.

## Измерения по сеансам

| Сеанс | Режим | Измеренная длительность | Передано, байт | Получено, байт | Применено / пропущено |
|---|---|---:|---:|---:|---:|
| 1 | AUTO, `n=0`, QUIC→TCP false, `rest=split` | 13 266 мс | 94 224 | 29 974 | 5 / 3 |
| 2 | AUTO, `n=7`, QUIC→TCP false, `rest=direct` | 22 034 мс | 262 693 | 73 492 | 16 / 3 |
| 3 | `tlsrec-split`, `n=7`, QUIC→TCP true | 6 318 мс | 47 744 | 7 363 | 3 / 0 |
| 4 | AUTO, `n=7`, QUIC→TCP false | четыре окна ≈120 секунд, с 16:50:15 до 16:51:46 | 1,070,271 | 454,760 | 80 / 14 |

Последний сеанс не завершён в предоставленном журнале, поэтому сумма четырёх окон — не обязательно итог всего сеанса. В первом окне счётчики показывают только измеренную часть с момента начала отсчёта; `applied_total` и `skipped_total` являются **процессными**, а не сеансовыми значениями.

## Интерпретация

1. `zapret2_transfer_final` появился при каждом коротком сеансе. Новая диагностика после предыдущего полевого отчёта работает и позволяет отличать отсутствие наблюдений от настоящего нулевого трафика.
2. `zapret2_alpine_ready status=socket_probed process_alive=true` и `connected` встретились во всех четырёх подключениях. Признаков падения Alpine или явного `ACTIVATION_REJECTED` после старта VPN нет. В начале приложения есть одно INFO-сообщение об отложенном восстановлении активации, но запуск не заблокирован.
3. `selected=0` после установки hostlist из 7 доменов **ожидаемо**: это число `zapret2AdaptiveTargetsText`, отличающееся от `zapret2HostlistText` / `n=7`. В AUTO `all_tcp=true` и подбор действует для всех подходящих TCP-соединений.
4. `rest=split` с пустым hostlist меняется на `rest=direct` при `n=7`. Следовательно, это не строгий A/B-тест **только** автоподбора: меняются также правила маршрутизации для неперечисленных доменов.
5. Автор подтвердил **нулевую загрузку YouTube, включая текст** при открытии приложения после активации стратегий. Поэтому заявленный результат — **неуспех на уровне приложения**, независимо от положительных транспортных счётчиков. Объёмы данных и число срабатываний могут принадлежать другим приложениям, служебному трафику или не завершённым запросам. Тест `tlsrec-split` составил всего 6,3 секунды; нет per-flow диагностики DNS/TCP/TLS/HTTPS.
6. Счётчики `*_total` не равны суммам `*_delta` разных сессий: у них разные моменты снятия базового значения; переходы между сеансами могут содержать неучтённые в старом сеансе соединения. Это пока не доказательство некорректной арифметики.

## Следующая проверка

**Приоритет — определить стадию отказа, а не увеличивать число «применений» стратегии.** Сопоставить обычное открытие YouTube без экспериментального VPN и с ним в одной мобильной сети, разделить DNS/соединение TCP или QUIC/TLS handshake/получение HTTPS-ответа, не записывая URL и секреты. Для повторного A/B сравнить AUTO и `tlsrec-split` с одним hostlist и контролируемым QUIC→TCP, оставляя каждому варианту 1–2 минуты. Записать текстовую оценку ленты, миниатюр и видео рядом с `zapret2_transfer_window`/`zapret2_transfer_final`. Отдельно сопоставить IPv4/IPv6 и Wi-Fi/MOBILE. Если оператор не выпускает IP сервиса, только локальная десинхронизация не создаст доступного маршрута.
