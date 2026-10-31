package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.app.device.expect
import com.dpsmpx.dppass.diagnostics.DiagCode
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * Неожиданная ошибка в пути подключения (D-90, D-108) — тоже отказ с
 * причиной на экране, а не «Подключение…» навсегда: так висел путь на
 * API 26 (31.10.2026) — исключение в корутине на SupervisorJob гасло молча.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], shadows = [SandboxVpnBuilder::class])
class UnexpectedErrorPathTest {
    @Test
    fun unexpectedErrorEndsTheAttemptWithReason() {
        val reason = connectUntilFailed(LINK) { throw UnsupportedOperationException("синтетическая неожиданная ошибка") }
        expect(reason.code == DiagCode.INTERNAL_ERROR) { "неожиданная ошибка — не INTERNAL_ERROR: $reason" }
    }

    private companion object {
        const val LINK = "vless://00000000-0000-4000-8000-000000000033@203.0.113.33:443?security=tls&sni=c.example.com#Gamma"
    }
}
