# Второй полевой автотест Google HTTPS: MOBILE, AUTO n=0

- **Время в отчёте теста:** 2026-11-22 21:12:15 +03:00 = 18:12:15 UTC.
- **Время журнала запуска:** 18:10:38–18:11:07 UTC, т.е. представленный фрагмент журнала **заканчивается до автотеста**. Отсутствие `zapret2_stage_window` в фрагменте не доказывает отсутствие событий при тесте.
- **Контекст:** Android API 35, Xray 26.9.30; Alpine ready / tunnel connected; MOBILE; AUTO, QUIC→TCP=false; `rest=split`, `dns=doh`, `n=0`, `https_unmatched=true`; пользователь не сообщил о новом успешном открытии YouTube.
- **Итог:** все 16 из 16 HTTP-запросов получили проверенный TLS-ответ `301` от `google.com`, по 220 байт. **Даже plain прошёл 2/2**, что не даёт оснований приписывать успех DPI-стратегиям.
- **Исправленная медиана подтверждена полевым отчётом:** две центральные задержки усреднены, при необходимости отображается половина миллисекунды.

## Сравнение двух реальных запусков

| Стратегия | Запуск 20:56 +03, медиана мс | Запуск 21:12 +03, медиана мс | 21:12, результат |
|---|---:|---:|---|
| plain | 301 | 356 | 2/2 301 |
| split-1 | 270 | 345 | 2/2 301 |
| split | 300.5 | 352.5 | 2/2 301 |
| tlsrec-split | 364 | 270 | 2/2 301 |
| fake-3 | 981 | 854.5 | 2/2 301 |
| fake-5 | 458.5 | 474 | 2/2 301 |
| disorder | 796.5 | 856 | 2/2 301 |
| auto | 285 | 317.5 | 2/2 301 |

**Методологические ограничения:** порядок стратегий одинаковый, по две попытки, разные временные окна и настройки обычной маршрутизации (`n=7/rest=direct` в более раннем сеансе против `n=0/rest=split` в новом). Сам автотест использует приватные forced outbounds, поэтому выбор hostlist для обычных приложений не доказывает изменение пути теста. Все варианты получили 301; **нет дифференциального сигнала блокировки**. `applied_delta=2..3` иногда может отражать фоновые подключения, а не только тестируемое соединение. Не выбирать «лучший» обход по этим миллисекундам.

**Предложение для следующего программного этапа:** различить первичный 301 и конечный документ после ожидаемого Google-редиректа; отдельно добавить явный тест проблемного YouTube endpoint при соблюдении приватности, лимитов трафика и TLS-верификации. Принудительное автоизменение пользовательской VPN-стратегии по Google 301 не обосновано.

## Дословно полученный журнал и отчёт

```text
=== DPpass — журнал ===

=== Текущий сеанс ===
2026-11-22T18:10:38.377Z INFO app session_start version=0.7.54-dev api=35 abis=arm64-v8a,armeabi-v7a,armeabi debuggable=true
2026-11-22T18:10:39.008Z INFO app activity_create
2026-11-22T18:10:39.825Z INFO app geodata_ready set=dlc 63777333b7dd, DB-IP 2026-10 installed_now=true
2026-11-22T18:10:39.905Z INFO app engine_loaded backend=xray version=26.9.30
2026-11-22T18:10:50.776Z INFO app service_start by=app
2026-11-22T18:10:51.140Z INFO core zapret2_alpine_start status=initializing
2026-11-22T18:10:53.337Z INFO core zapret2_alpine_ready status=socket_probed process_alive=true
2026-11-22T18:10:53.338Z INFO core zapret2_planner mode=alpine status=selected
2026-11-22T18:10:53.339Z INFO core <redacted> all_tcp=true selected=0 quic_trials_enabled=true
2026-11-22T18:10:53.349Z INFO core tunnel_up routes=2 apps=ExceptApps
2026-11-22T18:10:53.404Z INFO core serverless rest=split dns=doh apps=all n=0 local_desync=auto quic_force_tcp=false https_unmatched=true
2026-11-22T18:10:54.229Z INFO core connected profile=dppass:serverless attempts=1 local_desync=true content_verified=false zapret2_planner=alpine
2026-11-22T18:10:54.292Z INFO app underlying_network state=available type=MOBILE
2026-11-22T18:11:07.693Z INFO app work_finished reason=activity_stop

=== DPpass — Zapret2 Google HTTPS autotest ===
Time: 2026-11-22T21:12:15+03:00
Network: MOBILE
Target: https://google.com/ (GET; verified TLS certificate)
Mode: experimental VpnService; QUIC->TCP=false
Scope: TCP/HTTPS; QUIC is not tested
Redirects: reported, not followed
Strategies: plain, split-1, split, tlsrec-split, fake-3, fake-5, disorder, auto
Attempts: 16

Summary:
plain: 2/2 HTTP replies; median_ms=356; outcomes=redirect,redirect
split-1: 2/2 HTTP replies; median_ms=345; outcomes=redirect,redirect
split: 2/2 HTTP replies; median_ms=352.5; outcomes=redirect,redirect
tlsrec-split: 2/2 HTTP replies; median_ms=270; outcomes=redirect,redirect
fake-3: 2/2 HTTP replies; median_ms=854.5; outcomes=redirect,redirect
fake-5: 2/2 HTTP replies; median_ms=474; outcomes=redirect,redirect
disorder: 2/2 HTTP replies; median_ms=856; outcomes=redirect,redirect
auto: 2/2 HTTP replies; median_ms=317.5; outcomes=redirect,redirect

Every attempt:
1. plain #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=442 applied_delta=0 skipped_delta=0
2. plain #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=270 applied_delta=0 skipped_delta=0
3. split-1 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=340 applied_delta=2 skipped_delta=0
4. split-1 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=350 applied_delta=1 skipped_delta=0
5. split #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=366 applied_delta=3 skipped_delta=0
6. split #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=339 applied_delta=1 skipped_delta=0
7. tlsrec-split #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=272 applied_delta=3 skipped_delta=0
8. tlsrec-split #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=268 applied_delta=1 skipped_delta=0
9. fake-3 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=844 applied_delta=1 skipped_delta=0
10. fake-3 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=865 applied_delta=2 skipped_delta=0
11. fake-5 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=587 applied_delta=1 skipped_delta=0
12. fake-5 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=361 applied_delta=1 skipped_delta=0
13. disorder #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=802 applied_delta=1 skipped_delta=0
14. disorder #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=910 applied_delta=1 skipped_delta=0
15. auto #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=331 applied_delta=1 skipped_delta=0
16. auto #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=304 applied_delta=1 skipped_delta=0

Applied/skipped deltas are process-wide and may include unrelated apps.
A Google HTTP response does not prove YouTube feed/video works.
DNS/TCP/TLS, IP reachability and routing can fail independently.
```
