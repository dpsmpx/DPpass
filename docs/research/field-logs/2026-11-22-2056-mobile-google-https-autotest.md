# Первое полевое испытание Google HTTPS one-button autotest — MOBILE

**Источник:** отчёт DPpass, присланный пользователем 22 ноября 2026 г., 20:56:53 +03:00. Android API 35 / arm64, мобильная сеть, экспериментальный VpnService, QUIC→TCP=false. Полный оригинальный текст сохранён ниже.

## Непосредственно подтверждено

- Отработали все **16 из 16** попыток (8 TCP-вариантов × 2). Каждый завершился `outcome=redirect` и вернул `HTTP 301` + 220 байт тела ответа, сертификат TLS успешно проверен.
- Контроль `plain` тоже **2/2**: данный endpoint `https://google.com/` доступен и без десинхронизации. Эффективность DPI-обхода ни одним из восьми вариантов **не выделена**.
- Редирект **не выполнялся**, поэтому `www.google.com`, конечный документ Google, ресурсы YouTube/Googlevideo и QUIC/HTTP3 **не проверены**. Особенно важно: предыдущие испытания в той же категории сети подтвердили полную незагрузку YouTube, включая текст; этот тест это не опровергает.
- `applied_delta` / `skipped_delta` — счетчики **процесса Xray**; в журнале не гарантируется атрибуция отдельного запроса. Повышенный `split #1 applied_delta=3` демонстрирует ограничение атрибуции.
- Две попытки каждой стратегии и фиксированный последовательный порядок недостаточны, чтобы уверенно сравнивать миллисекундные задержки; влияние LTE-сети, DNS, адаптивного Xray и фоновых соединений не контролируется.

## Коррекция статистики

Первый отчет содержит **ошибку кодирования** медианы для чётного количества успешных попыток: берётся верхний элемент отсортированного списка, а не среднее двух центральных. Оригинал ниже не меняется; правильные медианные времена при 2 попытках:

| Стратегия | Исходный отчёт median_ms | Математическая медиана, мс | HTTP 301 |
|---|---:|---:|---:|
| plain | 335 | 301 | 2/2 |
| split-1 | 275 | 270 | 2/2 |
| split | 323 | 300,5 | 2/2 |
| tlsrec-split | 394 | 364 | 2/2 |
| fake-3 | 1016 | 981 | 2/2 |
| fake-5 | 489 | 458,5 | 2/2 |
| disorder | 839 | 796,5 | 2/2 |
| auto | 292 | 285 | 2/2 |

В исправленном программном отчёте дробная медиана сохраняется точно в формате `.5` (`split=300.5`, `fake-5=458.5`, `disorder=796.5`). Строка исходного отчёта ниже остаётся неизменной.

## Следующие вопросы

- Результат `google.com` не является успехом обхода DPI; не выставлять стратегии метку «лучше» при равном 2/2 и доступном `plain`.
- Для проверки реальной загрузки страниц опционально и явно добавить **следование ожидаемому редиректу** или прямую проверку `www.google.com` с верификацией TLS, HTML-статуса и тела, с ограничением запросов/трафика и временем. Для диагностики YouTube нужен независимый целевой тест; успешность Google не экстраполировать на Googlevideo.
- На следующем этапе предпочтительнее получать данные из приложения для проблемного сервиса, сохраняя конфиденциальность, чем оптимизировать стратегии по миллисекундам Google.

## Исходный отчёт

```text
=== DPpass — Zapret2 Google HTTPS autotest ===
Time: 2026-11-22T20:56:53+03:00
Network: MOBILE
Target: https://google.com/ (GET; verified TLS certificate)
Mode: experimental VpnService; QUIC->TCP=false
Scope: TCP/HTTPS; QUIC is not tested
Redirects: reported, not followed
Strategies: plain, split-1, split, tlsrec-split, fake-3, fake-5, disorder, auto
Attempts: 16

Summary:
plain: 2/2 HTTP replies; median_ms=335; outcomes=redirect,redirect
split-1: 2/2 HTTP replies; median_ms=275; outcomes=redirect,redirect
split: 2/2 HTTP replies; median_ms=323; outcomes=redirect,redirect
tlsrec-split: 2/2 HTTP replies; median_ms=394; outcomes=redirect,redirect
fake-3: 2/2 HTTP replies; median_ms=1016; outcomes=redirect,redirect
fake-5: 2/2 HTTP replies; median_ms=489; outcomes=redirect,redirect
disorder: 2/2 HTTP replies; median_ms=839; outcomes=redirect,redirect
auto: 2/2 HTTP replies; median_ms=292; outcomes=redirect,redirect

Every attempt:
1. plain #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=335 applied_delta=0 skipped_delta=0
2. plain #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=267 applied_delta=0 skipped_delta=0
3. split-1 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=275 applied_delta=1 skipped_delta=0
4. split-1 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=265 applied_delta=1 skipped_delta=0
5. split #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=323 applied_delta=3 skipped_delta=0
6. split #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=278 applied_delta=1 skipped_delta=0
7. tlsrec-split #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=334 applied_delta=1 skipped_delta=0
8. tlsrec-split #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=394 applied_delta=1 skipped_delta=0
9. fake-3 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=1016 applied_delta=1 skipped_delta=0
10. fake-3 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=946 applied_delta=1 skipped_delta=0
11. fake-5 #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=489 applied_delta=1 skipped_delta=0
12. fake-5 #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=428 applied_delta=1 skipped_delta=0
13. disorder #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=754 applied_delta=1 skipped_delta=0
14. disorder #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=839 applied_delta=1 skipped_delta=0
15. auto #1: outcome=redirect http=301 body_bytes=220 elapsed_ms=292 applied_delta=1 skipped_delta=0
16. auto #2: outcome=redirect http=301 body_bytes=220 elapsed_ms=278 applied_delta=1 skipped_delta=0

Applied/skipped deltas are process-wide and may include unrelated apps.
A Google HTTP response does not prove YouTube feed/video works.
DNS/TCP/TLS, IP reachability and routing can fail independently.
```
