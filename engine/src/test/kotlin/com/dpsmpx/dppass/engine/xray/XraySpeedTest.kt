package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.nio.ByteBuffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Замер через туннель (D-61): пинг, jitter, скорость; отказы; договор ответа моста. */
class XraySpeedTest {
    private fun result(vararg pingsMicros: Long, received: Long = 0, transfer: Long = 0, outcome: DnsProbeOutcome = DnsProbeOutcome.OK, text: String = "") =
        SpeedProbeResult(outcome, pingsMicros.toList(), received, transfer, text)

    @Test
    fun pingIsMedianJitterIsMeanStepSpeedIsBodyOverTransfer() {
        val r = assertIs<Outcome.Success<SpeedReport>>(
            XraySpeed.report(result(40_000, 60_000, 50_000, 45_000, 55_000, received = 12_500_000, transfer = 5_000_000)),
        )
        val s = r.value
        assertEquals(50.0, s.pingMillis)
        assertEquals(40.0, s.minPingMillis)
        // |60−40| + |50−60| + |45−50| + |55−45| = 20 + 10 + 5 + 10 = 45; 45 / 4 = 11,25.
        assertEquals(11.25, s.jitterMillis)
        assertEquals(20_000_000, s.downloadBitsPerSecond, "12,5 МБ за 5 с — 20 Мбит/с")
        assertEquals(5_000, s.transferMillis)
        assertEquals(5, s.pings)
        val even = XraySpeed.summary(result(10_000, 30_000))
        assertEquals(20.0, even.pingMillis)
        assertEquals(20.0, even.jitterMillis)
        assertEquals(0, XraySpeed.summary(result(10_000)).downloadBitsPerSecond, "без загрузки скорость не выдумывается")
        assertEquals(null, s.stalledAfterMillis, "шли до конца")
    }

    @Test
    fun dataStoppingEarlyIsAStallNotASlowLink() {
        // Телефон, 17.10.2026: ~237 КБ за 8 с два раза подряд — пришли за 1,2 с, дальше тишина.
        val frozen = SpeedProbeResult(DnsProbeOutcome.OK, listOf(50_000), 237_283, 8_000_000, "", lastByteMicros = 1_200_000)
        val s = XraySpeed.summary(frozen)
        assertEquals(1_200, s.stalledAfterMillis)
        assertEquals(237_283L * 8 * 1_000_000 / 8_000_000, s.downloadBitsPerSecond, "средняя за срок — как была")
        assertEquals(237_283L * 8 * 1_000_000 / 1_200_000, s.activeBitsPerSecond, "до остановки — быстрее")
        // Тишина меньше порога — не остановка: медленный, но живой канал.
        val slow = SpeedProbeResult(DnsProbeOutcome.OK, listOf(50_000), 237_283, 8_000_000, "", lastByteMicros = 7_000_000)
        assertEquals(null, XraySpeed.summary(slow).stalledAfterMillis)
    }

    @Test
    fun failuresHaveCodesAndRedactedCoreText() {
        val cases = mapOf(
            DnsProbeOutcome.UNREACHABLE to DiagCode.ENDPOINT_UNREACHABLE,
            DnsProbeOutcome.TLS to DiagCode.TLS_HANDSHAKE_FAILED,
            DnsProbeOutcome.STALLED to DiagCode.PAYLOAD_STALLED,
            DnsProbeOutcome.BAD_ANSWER to DiagCode.HEALTH_CHECK_FAILED,
            DnsProbeOutcome.NOT_RUNNING to DiagCode.HEALTH_CHECK_FAILED,
            DnsProbeOutcome.CONTRACT to DiagCode.HEALTH_CHECK_FAILED,
        )
        for ((outcome, code) in cases) {
            val secret = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"
            val f = assertIs<Outcome.Failure>(
                XraySpeed.report(result(outcome = outcome, text = "dial https://speed.example.net/$secret: refused")),
                outcome.name,
            )
            val d = f.errors.single()
            assertEquals(code, d.code, outcome.name)
            // Текст ядра — через Redactor, как у пробы здоровья (T3); адреса скрывает журнал уровня STRICT.
            assertFalse(d.causes.any { secret in it.toString() }, "токен в причине — редактируется")
            assertTrue(d.causes.isNotEmpty(), "текст ядра — в цепочке причин (D-22)")
        }
    }

    @Test
    fun bridgeAnswerFollowsTheContract() {
        val pings = listOf(41_000L, 4_000_000_000L)
        val answer = ByteBuffer.allocate(2 + pings.size * 4 + 8 + 4 + 4).apply {
            put(DnsProbeOutcome.OK.code.toByte())
            put(pings.size.toByte())
            pings.forEach { putInt(it.toInt()) }
            putLong(26_214_400)
            putInt(7_999_000)
            putInt(7_998_000)
        }.array() + "текст".encodeToByteArray()
        val r = XrayJni.decodeSpeed(answer)
        assertEquals(DnsProbeOutcome.OK, r.outcome)
        assertEquals(pings, r.pingMicros, "мкс — без знака")
        assertEquals(26_214_400, r.receivedBytes)
        assertEquals(7_999_000, r.transferMicros)
        assertEquals(7_998_000, r.lastByteMicros)
        assertEquals("текст", r.text)
        assertEquals(DnsProbeOutcome.CONTRACT, XrayJni.decodeSpeed(byteArrayOf(0, 3, 0, 0)).outcome, "короче заявленного")
        assertEquals(DnsProbeOutcome.CONTRACT, XrayJni.decodeSpeed(byteArrayOf()).outcome)
        assertTrue("текст" !in r.toString(), "текст ядра — не в toString")
    }
}
