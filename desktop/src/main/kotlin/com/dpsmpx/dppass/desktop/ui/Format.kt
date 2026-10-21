package com.dpsmpx.dppass.desktop.ui

import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter
import java.util.Locale

/** Числа и время для окна — по-русски. */
object Format {
    private val DATE = DateTimeFormatter.ofPattern("d MMM, HH:mm", Locale.forLanguageTag("ru"))

    fun bytes(n: Long): String {
        if (n < KIB) return "$n Б"
        val units = listOf("КБ", "МБ", "ГБ", "ТБ")
        var v = n.toDouble() / KIB
        var i = 0
        while (v >= KIB && i < units.lastIndex) {
            v /= KIB
            i++
        }
        return String.format(Locale.forLanguageTag("ru"), "%.1f %s", v, units[i])
    }

    fun duration(millis: Long): String {
        val s = (millis / MS).coerceAtLeast(0)
        val h = s / HOUR
        val m = s % HOUR / MINUTE
        val sec = s % MINUTE
        return if (h > 0) "%d:%02d:%02d".format(h, m, sec) else "%d:%02d".format(m, sec)
    }

    fun date(millis: Long): String = DATE.format(Instant.ofEpochMilli(millis).atZone(ZoneId.systemDefault()))

    private const val KIB = 1024
    private const val MS = 1000
    private const val MINUTE = 60
    private const val HOUR = 3600
}
