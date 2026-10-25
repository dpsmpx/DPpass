package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.UsageAlert
import com.dpsmpx.dppass.connection.UsageBytes
import com.dpsmpx.dppass.connection.UsageSummary
import com.dpsmpx.dppass.network.NetworkType
import java.time.LocalDate
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Учёт трафика (D-92) словами окна — по-русски, как на телефоне. */
object UsageText {
    private val DAY = DateTimeFormatter.ofPattern("d MMM", Locale.forLanguageTag("ru"))

    fun day(d: LocalDate): String = DAY.format(d)

    /** Строка «Подключения»: «Трафик через сервер: сегодня 120 МБ · с 1 окт. — 3,2 ГБ · мобильная 2,1 ГБ из 15,0 ГБ». */
    fun line(s: UsageSummary): String = listOfNotNull(
        "Трафик через сервер: сегодня ${Format.bytes(s.todayTotal.total)}",
        "с ${day(s.periodStart)} — ${Format.bytes(s.periodTotal.total)}",
        s.settings.mobileLimitBytes?.let { "мобильная ${Format.bytes(s.mobilePeriodBytes)} из ${Format.bytes(it)}" },
    ).joinToString(" · ")

    /** Сети отчёта: мобильная и Wi-Fi — всегда, проводная и прочие — если в них что-то было. */
    fun networks(by: Map<NetworkType, UsageBytes>): List<Pair<String, UsageBytes>> {
        val other = listOf(NetworkType.ETHERNET, NetworkType.OTHER).mapNotNull(by::get).fold(UsageBytes.ZERO, UsageBytes::plus)
        return listOf("Мобильная сеть" to (by[NetworkType.MOBILE] ?: UsageBytes.ZERO), "Wi-Fi" to (by[NetworkType.WIFI] ?: UsageBytes.ZERO)) +
            if (other.total > 0) listOf("Другие сети" to other) else emptyList()
    }

    fun bytes(b: UsageBytes): String = "${Format.bytes(b.total)} · ↓ ${Format.bytes(b.down)} · ↑ ${Format.bytes(b.up)}"

    fun alert(a: UsageAlert): String =
        "Через сервер в мобильной сети с ${day(a.periodStart)}: ${Format.bytes(a.usedBytes)}, порог — ${Format.bytes(a.limitBytes)}. Туннель работает."

    const val ALERT_TITLE: String = "Порог мобильного трафика пройден"

    const val NOTE: String = "Считается трафик через сервер — то, что оператор видит как зарубежный; сайты напрямую не считаются. " +
        "Это счёт DPpass на этом ПК: у оператора он другой — на накладные расходы протокола и трафик вне туннеля. Мобильная сеть — " +
        "модем ПК (интерфейс ww*); точка доступа телефона для ПК — Wi-Fi или провод."
}
