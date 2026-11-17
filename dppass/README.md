# DPpass — сборка 0.7.53-dev без подписи

Собрана из коммита `d98357d` ветки `claude/disable-auto-server-switch-8kn461` (PR в `main`). К коду проекта эта ветка не относится, истории у неё нет, в `main` не вливается.

**Не релиз** (`CLAUDE.md`). APK **без подписи**: подписать своим ключом в Termux — `sh resign-apk.sh dppass-0.7.53-dev-d98357d-arm64-v8a-unsigned.apk` (ключ и пароли — `dppass.release.*` в `~/.gradle/gradle.properties`, см. шапку скрипта). Пакет — `com.dpsmpx.dppass`, ярлык «DPpass» (D-114): ставится поверх 0.7.52-dev.

Что нового по сравнению с 0.7.52-dev:

- «Настройки» → «Эксперимент: подделка и перестановка» (по умолчанию выключен) → «Замер А/Б» (D-116): к выбранному серверу при выключенном VPN — без приёма, с разбиением ClientHello, с перестановкой (начало с TTL 1) и с подделкой для каждого TTL из диапазона, вперемешку по 10 попыток. Итог — на экране и в журнале (без адресов). Обычное подключение приём не использует.
- Закрепление сервера при выключенном автопереключении (D-113) — без изменений с 0.7.52-dev.

| Файл | ABI | SHA-256 |
|---|---|---|
| `dppass-0.7.53-dev-d98357d-arm64-v8a-unsigned.apk` | arm64-v8a | `56a9cfa0414e205ec21f72ac36baa6e9564877c22bc10249e7313f0899c73586` |
| `dppass-0.7.53-dev-d98357d-armeabi-v7a-unsigned.apk` | armeabi-v7a | `0b66b1e63ee8c1326c3df699d661ebcb88974de779a3182f790ac3c893edba88` |
| `dppass-0.7.53-dev-d98357d-x86_64-unsigned.apk` | x86_64 | `3b1504b6b745f7ccd1b46e2d60d6307e8fd4990a2f8c2b3aa71fc402c39e341d` |

Проверено: `tools/hostcheck/run.sh --full` на `d98357d` — 36 из 36, включая шаги Windows; `sign_apks.py --unsigned` → `check_apk.py --abi --release` на `d98357d`.
