#!/usr/bin/env bash
# Тесты интерфейса на телефоне (D-75): собрать отладочный и тестовый APK,
# поставить их через adb и запустить DeviceTestRunner.
#
#   tools/device/run_tests.sh                  — все тесты
#   tools/device/run_tests.sh Launch Navigation — только с этими словами в имени
#   NO_BUILD=1 tools/device/run_tests.sh       — без сборки: APK уже собраны
#
# Нужен adb, который видит телефон (`adb devices` → device): с компьютера по
# USB или из Termux на том же телефоне через беспроводную отладку
# (TODO.md, «На устройстве», «Тесты на телефоне»).
#
# Тесты только смотрят: ничего не импортируют, не подключают и не меняют
# (check_device_tests.py). Но am instrument перезапускает процесс DPpass —
# туннель на время тестов падает.
set -euo pipefail
cd "$(dirname "$0")/../.."

RUNNER=com.dpsmpx.dppass.test/com.dpsmpx.dppass.app.device.DeviceTestRunner
APP=app/build/outputs/apk/debug/app-debug.apk
TESTS=app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk

if ! command -v adb >/dev/null; then
    echo "✗ нет adb. В Termux: pkg install android-tools" >&2
    exit 2
fi
if [ "$(adb get-state 2>/dev/null || true)" != "device" ]; then
    echo "✗ adb не видит телефон (adb devices). Беспроводная отладка: adb pair, затем adb connect" >&2
    exit 2
fi

if [ -z "${NO_BUILD:-}" ]; then
    ./gradlew --console=plain :app:assembleDebug :app:assembleDebugAndroidTest
fi
for apk in "$APP" "$TESTS"; do
    [ -f "$apk" ] || { echo "✗ нет $apk — соберите без NO_BUILD" >&2; exit 2; }
done

# -r — поверх установленного, с его данными. Отказ INSTALL_FAILED_UPDATE_INCOMPATIBLE —
# установленный DPpass подписан другим ключом: тесты должны собираться там же, где он.
adb install -r "$APP"
adb install -r "$TESTS"

args=()
if [ $# -gt 0 ]; then
    args=(-e tests "$(IFS=,; echo "$*")")
fi
echo "Туннель DPpass на время тестов упадёт: am instrument перезапускает приложение."
out=$(adb shell am instrument -w "${args[@]}" "$RUNNER" | tr -d '\r')
echo "$out"
# Итог запускателя — последняя строка: «Все N тестов прошли.» или «Не прошли …».
if grep -q '^Все [0-9]* тестов прошли\.$' <<<"$out"; then
    exit 0
fi
exit 1
