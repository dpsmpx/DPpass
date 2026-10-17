#!/usr/bin/env bash
# hostcheck — все проверки DPpass одной командой (docs/PROCESS.md, «Проверки»).
# Обёртка над DP Verify (D-50): прежние ключи, проверки — tools/dpv/dpv по
# профилю tools/dpverify.toml.
#
#   tools/hostcheck/run.sh            dpv run full — всё, что можно на этой машине; пропуск — громко, но не ошибка
#   tools/hostcheck/run.sh --quick    dpv run static — только быстрые проверки (без Gradle)
#   tools/hostcheck/run.sh static     то же построчно — для проверки subsystem.dppass DPmetaApp (D-52)
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

# DPpass — подсистема DPmetaApp в dppass/ (D-52). DP Verify считает корнем
# проекта вершину git (`git rev-parse --show-toplevel`), а не каталог профиля,
# и внутри DPmetaApp увидел бы весь его репозиторий. Поэтому там проверки идут
# в представлении поддерева: свой каталог git в build/ (вне коммитов), рабочее
# дерево — этот каталог, коммит — его текущее содержимое. Вне DPmetaApp, в
# своём клоне, представление не нужно.
VIEW_OUTER=""
view() {
  local top
  top="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" || return 0
  [ "$(cd "$top" && pwd -P)" = "$(pwd -P)" ] && return 0
  VIEW_OUTER="$top"
  local gd="$ROOT/build/dpv-view.git"
  if [ ! -d "$gd" ]; then
    mkdir -p "$ROOT/build"
    git init -q --bare "$gd" || exit 3
    git --git-dir="$gd" config core.bare false
  fi
  export GIT_DIR="$gd" GIT_WORK_TREE="$ROOT"
  [ "${1:-}" = env ] && return 0
  git add -A . || exit 3
  local outer
  outer="$(git -C "$top" --git-dir="$top/.git" --work-tree="$top" rev-parse --short=12 HEAD 2>/dev/null)"
  git -c user.name=dppass-view -c user.email=dppass-view@localhost commit -q --allow-empty \
    -m "dppass/ из DPmetaApp ${outer:-?}" || exit 3
}

# --full — на закоммиченном дереве: в представлении всё «закоммичено», поэтому
# чистоту dppass/ проверяем в самом DPmetaApp, до представления.
committed_or_exit() {
  local top
  top="$(git -C "$ROOT" rev-parse --show-toplevel 2>/dev/null)" || return 0
  [ "$(cd "$top" && pwd -P)" = "$(pwd -P)" ] && return 0
  if [ -n "$(git -C "$ROOT" status --porcelain -- . 2>/dev/null)" ]; then
    echo "✗ --full: в dppass/ есть незакоммиченные изменения — прогон перед слиянием идёт на закоммиченном дереве"
    git -C "$ROOT" status --short -- . | head -20
    exit 2
  fi
}

note() { # что именно проверено, если проверки шли в представлении
  [ -n "$VIEW_OUTER" ] || return 0
  echo "dppass/ в DPmetaApp $(git -C "$VIEW_OUTER" --git-dir="$VIEW_OUTER/.git" --work-tree="$VIEW_OUTER" rev-parse --short=12 HEAD), дерево dppass/ $(git rev-parse --short=12 'HEAD^{tree}')"
}

# Итог --full — своей копией: корневой прогон DPmetaApp запускает здесь static
# (subsystem.dppass), и build/dpv/last после него — уже не --full, а в описание
# PR идёт итог --full (D-52). Копируется каталог именно этого прогона: если DP
# Verify прогона не записал, старая копия не подменяется чужой.
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
  "") view; note; exec "$PY" tools/dpv/dpv run full ;;
  --quick) view; note; exec "$PY" tools/dpv/dpv run static ;;
  static) view; note; exec "$PY" tools/dpv/dpv run static --verbose ;;
  --full) committed_or_exit; view; note; full_ci; exit $? ;;
  report)
    view env
    [ -f "$FULL_COPY/report.json" ] && exec "$PY" tools/dpv/dpv report --md --run "$FULL_COPY"
    echo "(прогона --full здесь ещё не было — итог последнего прогона)" >&2
    exec "$PY" tools/dpv/dpv report --md ;;
  -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
  *) echo "неизвестный параметр: $1 (есть --quick, static, --full, report)"; exit 2 ;;
esac
