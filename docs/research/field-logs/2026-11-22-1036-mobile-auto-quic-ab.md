# Полевой журнал DPpass: Android 15, мобильная сеть, AUTO / QUIC A/B

- **Дата журнала:** 22.11.2026, 10:36:21–10:39:07 UTC (суффикс `Z`).
- **Источник:** журнал, переданный пользователем в переписке.
- **Среда:** Android API 35, ARM64, DPpass 0.7.54-dev, Xray 26.9.30, Alpine PRoot.
- **Действия:** AUTO без hostlist и `QUIC→TCP=false`; затем `true`; возврат к `false`; установка 7 доменов hostlist и переподключение; завершение VPN.
- **Статус:** только наблюдения. Успех YouTube/видео не заявлен и не подтверждён приложением.
- **Конфиденциальность:** исходный журнал уже скрывает потенциально чувствительные события меткой `<redacted>`; имена посещённых сайтов не добавлялись.
- **Изменения:** только запись отчёта; исходный код DPpass не изменён.

## Исходный журнал (без исправлений)

```text
=== DPpass — журнал ===

=== Текущий сеанс ===
2026-11-22T10:36:21.237Z INFO app session_start version=0.7.54-dev api=35 abis=arm64-v8a,armeabi-v7a,armeabi debuggable=true
2026-11-22T10:36:22.056Z INFO app activity_create
2026-11-22T10:36:23.583Z INFO app geodata_ready set=dlc 63777333b7dd, DB-IP 2026-10 installed_now=true
2026-11-22T10:36:23.705Z INFO app engine_loaded backend=xray version=26.9.30
2026-11-22T10:36:36.778Z INFO app service_start by=app
2026-11-22T10:36:37.161Z INFO core zapret2_alpine_start status=initializing
2026-11-22T10:36:39.125Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T10:36:39.126Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T10:36:39.126Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T10:36:39.130Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T10:36:39.140Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T10:36:39.617Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T10:36:39.703Z INFO app underlying_network state=available type=MOBILE
2026-11-22T10:36:41.614Z INFO app work_finished reason=activity_stop
2026-11-22T10:37:08.990Z INFO core zapret2_transfer_window up_bytes=487883 down_bytes=124610 applied_delta=27 skipped_delta=8 applied_total=28 skipped_total=9
2026-11-22T10:37:31.422Z INFO app work_finished reason=activity_stop
2026-11-22T10:37:39.396Z INFO core zapret2_transfer_window up_bytes=352648 down_bytes=101163 applied_delta=32 skipped_delta=2 applied_total=60 skipped_total=11
2026-11-22T10:37:39.801Z INFO app service_reconnect by=user
2026-11-22T10:37:41.232Z INFO core zapret2_alpine_start status=initializing
2026-11-22T10:37:41.398Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T10:37:41.398Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T10:37:41.399Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=false
2026-11-22T10:37:41.400Z WARNING core <redacted> reason=force_tcp_enabled
2026-11-22T10:37:41.400Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T10:37:41.409Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=true https_unmatched=true
2026-11-22T10:37:41.695Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T10:37:41.717Z INFO app underlying_network state=available type=MOBILE
2026-11-22T10:37:44.294Z INFO app work_finished reason=activity_stop
2026-11-22T10:38:11.089Z INFO core zapret2_transfer_window up_bytes=577336 down_bytes=1903969 applied_delta=26 skipped_delta=8 applied_total=98 skipped_total=19
2026-11-22T10:38:32.121Z INFO app service_reconnect by=user
2026-11-22T10:38:33.330Z INFO core zapret2_alpine_start status=initializing
2026-11-22T10:38:33.466Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T10:38:33.467Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T10:38:33.467Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T10:38:33.468Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T10:38:33.476Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T10:38:33.822Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T10:38:33.843Z INFO app underlying_network state=available type=MOBILE
2026-11-22T10:38:37.795Z INFO core zapret2_hostlist_set n=7
2026-11-22T10:38:38.099Z INFO app service_reconnect by=user
2026-11-22T10:38:39.260Z INFO core zapret2_alpine_start status=initializing
2026-11-22T10:38:39.317Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T10:38:39.317Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T10:38:39.318Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T10:38:39.318Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T10:38:39.326Z INFO core serverless rest=direct dns=doh apps=all n=7 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T10:38:39.675Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T10:38:39.704Z INFO app underlying_network state=available type=MOBILE
2026-11-22T10:38:41.600Z INFO app work_finished reason=activity_stop
2026-11-22T10:38:58.482Z INFO app work_finished reason=activity_stop
2026-11-22T10:39:06.616Z INFO app service_revoked
2026-11-22T10:39:07.830Z INFO app work_finished reason=service_stop
```

## Наблюдения из журнала

| Конфигурация | Окно | Исходящий трафик | Входящий трафик | Изменения applied/skipped |
|---|---|---:|---:|---:|
| AUTO, пустой список, QUIC→TCP off | 10:36:39–10:37:08 | 487883 | 124610 | +27/+8 |
| AUTO, пустой список, QUIC→TCP off | 10:37:08–10:37:39 | 352648 | 101163 | +32/+2 |
| AUTO, пустой список, QUIC→TCP on | 10:37:41–10:38:11 | 577336 | 1903969 | +26/+8 |
| AUTO, 7 доменов, QUIC→TCP off | 10:38:39–10:39:07 | Нет полного 30-секундного окна | Нет полного 30-секундного окна | Не измерено |

**Важно:** единственное окно с ~1,9 МБ входящего трафика совпадает с `QUIC→TCP=true`. Это не доказывает загрузку YouTube: суммарная статистика VPN включает разные приложения и сервисы. Следует сверить с действием пользователя и конкретными доменами/потоками, не сохраняя пользовательские URL. `service_revoked` означает отзыв VPN системой/пользователем, точный источник из одного журнала не установлен.
