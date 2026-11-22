# Android 15 / MOBILE: AUTO → tlsrec-split / QUIC→TCP

**Дата:** 22 ноября 2026 года, 15:24:25–15:25:11 UTC.  
**Источник:** журнал, присланный владельцем проекта. Сохранён дословно, включая `<redacted>`.  
**Среда:** DPpass 0.7.54-dev, Android API 35, Xray 26.9.30, Alpine ARM64.  
**Исход:** запуск планировщика и туннеля подтверждён, фактическое применение DPI и доступность конкретных сервисов — не проверены этим журналом.

## Исходный журнал

```text
=== DPpass — журнал ===

=== Текущий сеанс ===
2026-11-22T15:24:25.951Z INFO app session_start version=0.7.54-dev api=35 abis=arm64-v8a,armeabi-v7a,armeabi debuggable=true
2026-11-22T15:24:26.713Z INFO app activity_create
2026-11-22T15:24:27.757Z INFO app geodata_ready set=dlc 63777333b7dd, DB-IP 2026-10 installed_now=true
2026-11-22T15:24:27.897Z INFO app engine_loaded backend=xray version=26.9.30
2026-11-22T15:24:28.108Z INFO core diagnostic code=ACTIVATION_REJECTED message=активация выполняется: восстановление отложено
2026-11-22T15:24:40.016Z INFO app service_start by=app
2026-11-22T15:24:40.282Z INFO core zapret2_alpine_start status=initializing
2026-11-22T15:24:41.928Z INFO app work_finished reason=activity_stop
2026-11-22T15:24:43.861Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T15:24:43.862Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T15:24:43.866Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T15:24:43.949Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T15:24:44.075Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T15:24:45.039Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T15:24:45.106Z INFO app underlying_network state=available type=MOBILE
2026-11-22T15:25:08.964Z INFO app service_reconnect by=user
2026-11-22T15:25:10.225Z INFO core zapret2_alpine_start status=initializing
2026-11-22T15:25:10.493Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T15:25:10.493Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T15:25:10.494Z INFO core <redacted> all_tcp=false selected=0 quic_trials_enabled=false
2026-11-22T15:25:10.494Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T15:25:10.511Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=tlsrec-split quic_force_tcp=true https_unmatched=true
2026-11-22T15:25:10.839Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T15:25:10.893Z INFO app underlying_network state=available type=MOBILE
2026-11-22T15:25:11.503Z INFO app work_finished reason=activity_stop
```

## Разбор

- **15:24:43–15:24:45:** Alpine `socket_probed`, выбран планировщик Alpine; `local_desync=auto`, `all_tcp=true`, `n=0`, `quic_force_tcp=false`, `quic_trials_enabled=true`. Режим AUTO включён, выбранных вручную адресов ноль.
- **15:25:08–15:25:10:** пользователь инициировал переподключение; `local_desync=tlsrec-split`, `all_tcp=false`, `quic_force_tcp=true`, `quic_trials_enabled=false`. Это **другой** режим, с фиксированной TCP-стратегией и заблокированным QUIC. Отсутствие глобального TCP AUTO ожидаемо.
- Начальный AUTO-туннель был подключён примерно 24 секунды до переподключения; последний показан лишь примерно на секунду после подключения. Периодический `zapret2_transfer_window` выводится примерно раз в 30 секунд, поэтому отсутствие таких записей **не доказывает отсутствие трафика**.
- В обоих запусках `content_verified=false`: успешное установление VPN не подтверждает загрузку YouTube/видео. Ни объёмы исходящего/входящего трафика, ни число применённых стратегий, ни HTTP-результаты в этом журнале не зафиксированы.
- `ACTIVATION_REJECTED` выведено с уровнем INFO и текстом об отложенном восстановлении; после него сервис успешно начал работу. Отдельной ошибки запуска по этому сообщению не установлено.
- `work_finished reason=activity_stop` — событие жизненного цикла Activity, само по себе не означает обрыв VPN.
- Конец предоставленного текста не содержит остановки VPN. Нельзя утверждать, что он был остановлен.

**Следующий замер:** в каждом варианте дать VPN поработать более 30 секунд, проверить конкретные действия (лента, картинки, воспроизведение), сопоставить окна `applied_delta/skipped_delta` и downstream. Полезный дальнейший программный шаг — добавить итоговое окно при коротком сеансе перед переподключением, не меняя маршрутизацию и стратегии.
