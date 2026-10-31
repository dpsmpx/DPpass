package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.diagnostics.DiagCode
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Ключевой путь «подключение и отказ» (D-90): сервер есть → «Подключить» →
 * согласие на VPN → сервис туннеля → туннель не поднялся → экран говорит, что не
 * подключено и почему, а кнопка снова подключает. На API 26, 29 и 36 (D-108);
 * неожиданная ошибка в том же пути — `UnexpectedErrorPathTest`. TUN на JVM нет:
 * Android здесь отвергает его так, как велит документ `establish()`, — дальше
 * всё настоящее: сервис, ядро Xray, состояние туннеля и экран.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], shadows = [SandboxVpnBuilder::class])
class ConnectPathTest {
    @Test
    fun failureShowsReasonAndConnectAgain() {
        // Android отвергает TUN (документ establish(): IllegalStateException) — отказ, а не «Подключение…» навсегда.
        val reason = connectUntilFailed(LINK) { throw IllegalStateException("синтетический отказ TUN") }
        expect(reason.code == DiagCode.TUN_ESTABLISH_FAILED) { "отказ — не TUN: $reason" }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#Alpha"
    }
}
