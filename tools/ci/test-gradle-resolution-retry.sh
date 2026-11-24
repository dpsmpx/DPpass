#!/usr/bin/env bash
set -euo pipefail
root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
cd "$tmp"
cat > gradlew <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
n=0
if [[ -f count ]]; then read -r n < count; fi
n=$((n+1))
echo "$n" > count
case "$MODE" in
  transient)
    if (( n == 1 )); then
      echo 'could not resolve plugin artifact'
      exit 7
    fi
    ;;
  persistent)
    echo 'could not resolve plugin artifact'
    exit 7
    ;;
  task)
    echo '> Task :app:test FAILED'
    echo 'Could not download'
    exit 9
    ;;
  other)
    echo 'compilation error'
    exit 6
    ;;
esac
EOF
chmod +x gradlew
# Suppress delay in isolated fixture only.
mkdir bin
printf '#!/usr/bin/env bash\nexit 0\n' > bin/sleep
chmod +x bin/sleep
export PATH="$tmp/bin:$PATH"
check() {
  rm -f count
  local mode="$1" expected_status="$2" expected_attempts="$3" status=0
  MODE="$mode" bash "$root/tools/ci/gradle-resolution-retry.sh" :test || status=$?
  [[ "$status" == "$expected_status" && "$(cat count)" == "$expected_attempts" ]]
}
check transient 0 2
check persistent 7 3
check task 9 1
check other 6 1
echo 'Gradle resolution retry fixtures passed'
