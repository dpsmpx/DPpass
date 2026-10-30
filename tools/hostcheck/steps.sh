#!/usr/bin/env bash
# Шаги проверки DPpass, которые не одна программа: их зовёт DP Verify командами
# профиля tools/dpverify.toml (D-50). Перенесены из tools/hostcheck/run.sh без
# изменения поведения; дым CLI — проверка smoke.cli DP Verify.
#
#   tools/hostcheck/steps.sh build         сборка и тесты ядра и build-logic, стиль Kotlin (с Android SDK — без :app:build: APK — шаг Android)
#   tools/hostcheck/steps.sh xray-bridge   мост Xray: библиотека для JVM хоста и тест JNI в этой JVM (D-25)
#   tools/hostcheck/steps.sh android-screens  экраны и ключевые пути на JVM: Robolectric с ядром Xray для хоста (D-86, D-90)
#   tools/hostcheck/steps.sh android-sdk   есть ли Android SDK (проба [[tool]] профиля)
#   tools/hostcheck/steps.sh android-ndk   есть ли NDK версии из каталога (проба [[tool]] профиля)
#   tools/hostcheck/steps.sh wine          есть ли wine64 — тесты моста для Windows (проба [[tool]] профиля, D-97)
#
# Код возврата: 0 — шаг прошёл; 1 — нет; 2 — неверный вызов.
set -u

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$ROOT" || exit 2

PY="${PYTHON:-python3}"
GRADLE=(./gradlew --console=plain --warning-mode=summary)

sdk_dir() { # тот же признак, что в settings.gradle.kts; печатает путь
  local dir="${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}"
  if [ -n "$dir" ] && [ -d "$dir" ]; then echo "$dir"; return 0; fi
  if [ -f local.properties ]; then
    dir="$(sed -n 's/^sdk\.dir=//p' local.properties | head -1)"
    [ -n "$dir" ] && [ -d "$dir" ] && { echo "$dir"; return 0; }
  fi
  return 1
}
android_sdk() { sdk_dir >/dev/null; }

# Тесты путей (D-90) действуют: конфигурацию проверяет настоящее ядро — библиотека моста для хоста,
# та же, что у XrayJniTest. Robolectric и AndroidX тестов — только по свойству dppass.robolectric.
android_screens() {
  "$PY" tools/xray/native.py host || return 1
  "${GRADLE[@]}" -Pdppass.robolectric -Pdppass.xray.lib=build/xray/host/libdppassxray.so :app:testDebugUnitTest
}

xray_bridge() {
  "$PY" tools/xray/native.py host || return 1
  local lib=build/xray/host/libdppassxray.so
  "${GRADLE[@]}" :tests:integration:xrayJniTest -Pdppass.xray.lib="$lib" || return 1
  "$PY" - <<'PYEOF' || return 1
import glob, xml.etree.ElementTree as ET
n = f = 0
for p in glob.glob("tests/integration/build/test-results/xrayJniTest/*.xml"):
    r = ET.parse(p).getroot()
    n += int(r.get("tests")); f += int(r.get("failures")) + int(r.get("errors"))
if n == 0 or f:
    raise SystemExit(f"✗ XrayJniTest: тестов {n}, отказов {f}")
print(f"✓ XrayJniTest: {n} тестов моста через JNI в JVM хоста")
PYEOF
}

build() {
  # :build-logic:test — логика сборки (личность пакета, D-47, D-49): `build`
  # корня включённую сборку не проверяет.
  # ktlintCheck — стиль Kotlin по .editorconfig (D-63).
  local tasks=(build :cli:installDist :build-logic:test ktlintCheck)
  android_sdk && tasks+=(-x :app:build)
  "${GRADLE[@]}" "${tasks[@]}"
}

android_ndk() { # NDK версии из каталога: им собирается libdppassxray.so для APK (D-25)
  local sdk ver
  sdk="$(sdk_dir)" || return 1
  ver="$(sed -n 's/^android-ndk *= *"\(.*\)"/\1/p' gradle/libs.versions.toml)"
  [ -n "$ver" ] && [ -f "$sdk/ndk/$ver/source.properties" ]
}

wine() { # wine64 в PATH или там, куда его кладёт пакет Ubuntu
  command -v wine64 >/dev/null || [ -x /usr/lib/wine/wine64 ]
}

case "${1:-}" in
  build) build ;;
  xray-bridge) xray_bridge ;;
  android-screens) android_screens ;;
  android-sdk) android_sdk ;;
  android-ndk) android_ndk ;;
  wine) wine ;;
  *) echo "steps.sh: шаг build, xray-bridge, android-screens, android-sdk, android-ndk или wine, а не «${1:-}»"; exit 2 ;;
esac
