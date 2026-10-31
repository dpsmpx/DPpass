package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import com.dpsmpx.dppass.engine.RouteKind
import java.text.NumberFormat
import java.util.Locale

/**
 * Подписи ячеек таблицы анализатора (D-106) на языке оболочки: на Android —
 * из ресурсов, на ПК — свои. Байты и скорость форматирует оболочка
 * ([bytes], [speed]) — как везде у неё.
 */
data class CellLabels(
    val open: String,
    val closed: String,
    val failed: String,
    val routeProxy: String,
    val routeDirect: String,
    val routeBlock: String,
    val routeDns: String,
    val inTun: String,
    val inLocal: String,
    val inShare: String,
    /** Свои запросы DPpass: проверка здоровья, замер — у них нет входа. */
    val inSelf: String,
    val noAnswer: String,
    /** Единицы времени: миллисекунды и секунды. */
    val ms: String,
    val s: String,
    /** Формат процента: «%d %%» или «%d%%». */
    val percent: String,
    val locale: Locale,
    val bytes: (Long) -> String,
    val speed: (Long) -> String,
    val none: String = "—",
)

/** Текст ячеек (D-106): одна логика на телефоне и ПК, подписи — от оболочки. */
object ConnectionCells {
    /** [app] — подпись владельца (на Android — ярлык приложения по имени пакета). */
    fun text(row: ConnectionRow, column: ConnColumn, l: CellLabels, app: (String) -> String = { it }): String {
        val c = row.connection
        return when (column) {
            ConnColumn.STATE -> state(c.state, l)
            ConnColumn.APP -> row.app?.let(app) ?: l.none
            ConnColumn.HOST -> row.host
            ConnColumn.PORT -> row.port?.toString() ?: l.none
            ConnColumn.NETWORK -> c.network.name
            ConnColumn.PROTOCOL -> c.protocol.ifEmpty { l.none }
            ConnColumn.ROUTE -> route(c, l)
            ConnColumn.INBOUND -> inbound(c, l)
            ConnColumn.DURATION -> duration(c.durationMillis, l)
            ConnColumn.IDLE -> duration(c.idleMillis, l)
            ConnColumn.FIRST_BYTE -> when {
                c.firstByteMillis >= 0 -> latency(c.firstByteMillis, l)
                c.state == ConnState.OPEN && c.ageMillis < ConnectionTable.NO_ANSWER_MILLIS -> l.none
                else -> l.noAnswer
            }
            ConnColumn.UP_RATE -> row.upRate?.let(l.speed) ?: l.none
            ConnColumn.DOWN_RATE -> row.downRate?.let(l.speed) ?: l.none
            ConnColumn.UP_BYTES -> l.bytes(c.upBytes)
            ConnColumn.DOWN_BYTES -> l.bytes(c.downBytes)
            ConnColumn.UP_CHUNKS -> count(c.upChunks, l)
            ConnColumn.DOWN_CHUNKS -> count(c.downChunks, l)
            ConnColumn.RECENT -> count(row.hostRecent.toLong(), l)
            ConnColumn.RELIABILITY -> row.reliability?.let { String.format(l.locale, l.percent, it) } ?: l.none
        }
    }

    fun state(s: ConnState, l: CellLabels): String = when (s) {
        ConnState.OPEN -> l.open
        ConnState.CLOSED -> l.closed
        ConnState.FAILED -> l.failed
    }

    fun route(c: EngineConnection, l: CellLabels): String = when (c.routeKind) {
        RouteKind.PROXY -> l.routeProxy
        RouteKind.DIRECT -> l.routeDirect
        RouteKind.BLOCK -> l.routeBlock
        RouteKind.DNS -> l.routeDns
        RouteKind.NONE -> l.none
        RouteKind.OTHER -> c.route
    }

    fun inbound(c: EngineConnection, l: CellLabels): String = when (c.inboundKind) {
        InboundKind.TUN -> l.inTun
        InboundKind.LOCAL -> l.inLocal
        InboundKind.SHARE -> l.inShare
        InboundKind.OTHER -> c.inbound.ifEmpty { l.inSelf }
    }

    /** Длительность: «45 с», «4:05», «1:02:03». */
    fun duration(millis: Long, l: CellLabels): String {
        val total = (millis / 1000).coerceAtLeast(0)
        if (total < 60) return "$total ${l.s}"
        val h = total / 3600
        val m = (total % 3600) / 60
        val sec = total % 60
        return if (h > 0) "%d:%02d:%02d".format(Locale.ROOT, h, m, sec) else "%d:%02d".format(Locale.ROOT, m, sec)
    }

    /** Время ответа: «120 мс», «1,2 с». */
    fun latency(millis: Long, l: CellLabels): String =
        if (millis < 1000) "$millis ${l.ms}" else String.format(l.locale, "%.1f %s", millis / 1000.0, l.s)

    fun count(n: Long, l: CellLabels): String = NumberFormat.getIntegerInstance(l.locale).format(n)

    /** Подписи строки для поиска (D-106): что видно в ячейках на языке оболочки. */
    fun searchLabels(row: ConnectionRow, l: CellLabels, app: (String) -> String = { it }): List<String> =
        listOfNotNull(state(row.state, l), route(row.connection, l), inbound(row.connection, l), row.app?.let(app))

    /** Образец самого широкого значения столбца — ширина не прыгает при обновлении. */
    fun sample(column: ConnColumn, l: CellLabels): String = when (column) {
        ConnColumn.STATE -> listOf(l.open, l.closed, l.failed).maxBy { it.length }
        ConnColumn.APP -> "W".repeat(14)
        ConnColumn.HOST -> "w".repeat(24)
        ConnColumn.PORT -> "65535"
        ConnColumn.NETWORK -> "TCP"
        ConnColumn.PROTOCOL -> "bittorrent"
        ConnColumn.ROUTE -> listOf(l.routeProxy, l.routeDirect, l.routeBlock, l.routeDns).maxBy { it.length }
        ConnColumn.INBOUND -> listOf(l.inTun, l.inLocal, l.inShare, l.inSelf).maxBy { it.length }
        ConnColumn.DURATION, ConnColumn.IDLE -> "00:00:00"
        ConnColumn.FIRST_BYTE -> listOf("999 ${l.ms}", l.noAnswer).maxBy { it.length }
        ConnColumn.UP_RATE, ConnColumn.DOWN_RATE -> l.speed(999L shl 20)
        ConnColumn.UP_BYTES, ConnColumn.DOWN_BYTES -> l.bytes(999L shl 20)
        ConnColumn.UP_CHUNKS, ConnColumn.DOWN_CHUNKS, ConnColumn.RECENT -> count(999_999, l)
        ConnColumn.RELIABILITY -> String.format(l.locale, l.percent, 100)
    }

    // ---- журнал уникальных ----

    /** [date] — дата и время по часам устройства в формате оболочки. */
    fun unique(e: UniqueEntry, column: UniqueColumn, l: CellLabels, date: (Long) -> String, app: (String) -> String = { it }): String =
        when (column) {
            UniqueColumn.APP -> e.key.app?.let(app) ?: l.none
            UniqueColumn.HOST -> e.key.host
            UniqueColumn.PORT -> e.key.port.toString()
            UniqueColumn.NETWORK -> e.key.network.name
            UniqueColumn.COUNT -> count(e.count, l)
            UniqueColumn.LAST -> date(e.lastMillis)
        }

    fun sample(column: UniqueColumn, l: CellLabels, date: (Long) -> String): String = when (column) {
        UniqueColumn.APP -> "W".repeat(14)
        UniqueColumn.HOST -> "w".repeat(24)
        UniqueColumn.PORT -> "65535"
        UniqueColumn.NETWORK -> "TCP"
        UniqueColumn.COUNT -> count(9_999_999, l)
        UniqueColumn.LAST -> date(SAMPLE_DATE)
    }

    /** 28.12.2026 23:58 — самое широкое время для образца. */
    private const val SAMPLE_DATE = 1_798_502_280_000L
}
