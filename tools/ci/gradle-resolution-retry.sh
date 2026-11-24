#!/usr/bin/env bash
# Retry only a Gradle dependency-resolution failure, never a task/test failure.
set -euo pipefail
log="$(mktemp)"
trap 'rm -f "$log"' EXIT
for attempt in 1 2 3; do
  set +e
  ./gradlew --no-daemon --console=plain "$@" 2>&1 | tee "$log"
  status=${PIPESTATUS[0]}
  set -e
  if (( status == 0 )); then exit 0; fi
  if (( attempt == 3 )); then exit "$status"; fi
  # The observed failure happens during configuration, before executing tasks.
  # Do not retry if a Gradle task has actually failed.
  if grep -Eq '^> Task .* FAILED|^Execution failed for task ' "$log"; then
    exit "$status"
  fi
  if ! grep -Eq 'could not resolve plugin artifact|Could not resolve all (files|artifacts|dependencies)|Could not (GET|HEAD|download)' "$log"; then
    exit "$status"
  fi
  echo "::warning::Gradle dependency resolution failed; retry $((attempt+1))/3 using the same pinned versions"
  sleep "$((attempt*10))"
done
