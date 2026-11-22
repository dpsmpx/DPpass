#!/usr/bin/env bash
# hostcheck — все проверки DPpass одной командой (docs/PROCESS.md, «Проверки»).
# Обёртка над DP Verify (D-50): прежние ключи, проверки — tools/dpv/dpv по
# профилю tools/dpverify.toml.
#
#   tools/hostcheck/run.sh            dpv run full — всё, что можно на этой машине; пропуск — громко, но не ошибка
#   tools/hostcheck/run.sh --quick    dpv run static — только быстрые проверки (без Gradle)
#   tools/hostcheck/run.sh --full     dpv run full --ci — перед слиянием (CI нет, D-23): на закоммиченном
#                                     дереве, каждый пропуск (нет Android SDK, NDK, Go) — ошибка
#   tools/hostcheck/run.sh report     dpv report --md — итог последнего --full для описания PR
#                                     (копия в build/dpv/full; без неё — итог последнего прогона)
#
# Код возврата — как у dpv: 0 — пройдено; 1 — есть ✗; 2 — неверный вызов
# или профиль; 3 — сбой DP Verify.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2
PY="${PYTHON:-python3}"

# Итог --full — своей копией: после --full часто идёт --quick, и build/dpv/last
# после него — уже не --full, а в описание PR идёт итог --full (docs/PROCESS.md,
# «Перед слиянием»). Копируется каталог именно этого прогона: если DP Verify
# прогона не записал, старая копия не подменяется чужой.
RUNS="build/dpv/runs"
FULL_COPY="build/dpv/full"
newest_run() { ls -1 "$RUNS" 2>/dev/null | tail -n 1; }
full_ci() {
  local before after rc
  before="$(newest_run)"
  "$PY" tools/dpv/dpv run full --ci
  rc=$?
  after="$(newest_run)"
  if [ -n "$after" ] && [ "$after" != "$before" ] && [ -f "$RUNS/$after/report.json" ]; then
    rm -rf "$FULL_COPY" && cp -R "$RUNS/$after" "$FULL_COPY"
  fi
  return "$rc"
}

case "${1:-}" in
  "") exec "$PY" tools/dpv/dpv run full ;;
  --quick) exec "$PY" tools/dpv/dpv run static ;;
  --full) full_ci; exit $? ;;
  report)
    [ -f "$FULL_COPY/report.json" ] && exec "$PY" tools/dpv/dpv report --md --run "$FULL_COPY"
    echo "(прогона --full здесь ещё не было — итог последнего прогона)" >&2
    exec "$PY" tools/dpv/dpv report --md ;;
  -h|--help) sed -n '2,14p' "$0"; exit 0 ;;
  *) echo "неизвестный параметр: $1 (есть --quick, --full, report)"; exit 2 ;;
esac
