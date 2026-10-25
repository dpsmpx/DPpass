package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.UsageAlert
import com.dpsmpx.dppass.connection.UsageBytes
import com.dpsmpx.dppass.connection.UsageSettings
import com.dpsmpx.dppass.connection.UsageSummary
import com.dpsmpx.dppass.desktop.ui.UsageText
import com.dpsmpx.dppass.network.NetworkType
import java.time.LocalDate
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Учёт трафика на ПК (D-92): строка окна, сети отчёта, уведомление рабочего стола. */
class UsageDesktopTest {
    private val gib = 1L shl 30

    private fun summary(limit: Long?) = UsageSummary(
        today = mapOf(NetworkType.WIFI to UsageBytes(0, 100L shl 20)),
        period = mapOf(NetworkType.MOBILE to UsageBytes(gib / 2, 3 * gib / 2), NetworkType.ETHERNET to UsageBytes(0, 1)),
        periodStart = LocalDate.of(2026, 10, 5),
        periodEnd = LocalDate.of(2026, 11, 5),
        resetAtMillis = null,
        settings = UsageSettings(5, limit),
    )

    @Test
    fun lineShowsTodayPeriodAndMobileLimit() {
        assertEquals("Трафик через сервер: сегодня 100,0 МБ · с 5 окт. — 2,0 ГБ", UsageText.line(summary(null)))
        assertEquals("Трафик через сервер: сегодня 100,0 МБ · с 5 окт. — 2,0 ГБ · мобильная 2,0 ГБ из 15,0 ГБ", UsageText.line(summary(15 * gib)))
    }

    @Test
    fun reportListsMobileAndWifiAlwaysOthersOnlyWhenUsed() {
        assertEquals(listOf("Мобильная сеть", "Wi-Fi"), UsageText.networks(summary(null).today).map { it.first })
        assertEquals(UsageBytes.ZERO, UsageText.networks(summary(null).today).first().second, "ноль — тоже ответ")
        assertEquals(listOf("Мобильная сеть", "Wi-Fi", "Другие сети"), UsageText.networks(summary(null).period).map { it.first })
    }

    @Test
    fun desktopNotificationGoesThroughNotifySendWithoutSecrets() {
        val calls = mutableListOf<List<String>>()
        val n = DesktopNotify { calls += it; CommandResult(0, "") }
        val alert = UsageAlert(16 * gib, 15 * gib, LocalDate.of(2026, 10, 5))
        assertTrue(n.show(UsageText.ALERT_TITLE, UsageText.alert(alert)))
        val text = "Через сервер в мобильной сети с 5 окт.: 16,0 ГБ, порог — 15,0 ГБ. Туннель работает."
        assertEquals(listOf("--app-name=DPpass", UsageText.ALERT_TITLE, text), calls.single())
        assertFalse(DesktopNotify { CommandResult(SystemCommand.NOT_FOUND, "нет") }.show("a", "b"), "нет notify-send — false, окно покажет полосу")
        assertTrue(DesktopNotify.BINARIES.all { it.startsWith("/") }, "не из PATH (T17)")
    }
}
