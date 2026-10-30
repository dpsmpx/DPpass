//go:build (linux || windows) && !dppass_testinbound

package bridge

import "github.com/xtls/xray-core/core"

// Сборка для APK: тестового входа нет, входы ядра — только TUN (T11).
const testInbounds = false

func testInboundAllowed(*core.InboundHandlerConfig) bool { return false }
