package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.RouteKind
import java.util.Locale

/**
 * Цвет ячейки таблицы анализатора (D-106) — смысл, а не краска: цвета
 * подбирает оболочка под свою тему. [HEAT_LOW]…[HEAT_HIGH] — насколько
 * велико значение (скорость, объём), как подсветка столбцов в диспетчере
 * задач.
 */
enum class Tone { NORMAL, MUTED, GOOD, INFO, WARN, BAD, HEAT_LOW, HEAT_MID, HEAT_HIGH }

/**
 * Столбец таблицы соединений (D-106). [numeric] — число: выравнивается
 * вправо и при первом нажатии сортируется по убыванию, как в `top`.
 */
enum class ConnColumn(val numeric: Boolean) {
    STATE(false),
    APP(false),
    HOST(false),
    PORT(true),
    NETWORK(false),
    PROTOCOL(false),
    ROUTE(false),
    INBOUND(false),
    DURATION(true),
    IDLE(true),
    FIRST_BYTE(true),
    UP_RATE(true),
    DOWN_RATE(true),
    UP_BYTES(true),
    DOWN_BYTES(true),
    UP_CHUNKS(true),
    DOWN_CHUNKS(true),
    RECENT(true),
    RELIABILITY(true),
}

/** Сортировка: столбец и направление. */
data class ConnSort(val column: ConnColumn, val descending: Boolean) {
    /** Нажатие на заголовок [c]: тот же столбец — обратный порядок, другой — его естественный. */
    fun toggled(c: ConnColumn): ConnSort = if (c == column) copy(descending = !descending) else ConnSort(c, c.numeric)
}

/**
 * Таблица анализатора (D-106) без интерфейса: порядок, поиск и цвета — одни
 * на телефоне и ПК. Оболочка только рисует.
 */
object ConnectionTable {
    /** Как `top`: сверху — кто сейчас больше получает. */
    val DEFAULT_SORT: ConnSort = ConnSort(ConnColumn.DOWN_RATE, descending = true)

    /** Открытое соединение без ответа дольше этого — «нет ответа». */
    const val NO_ANSWER_MILLIS: Long = 5_000

    /** Открытое соединение без данных дольше этого — дремлет. */
    const val DORMANT_MILLIS: Long = 60_000

    /** Ответ: до этого — быстрый, до [SLOW_ANSWER_MILLIS] — обычный, дальше — медленный, после [BAD_ANSWER_MILLIS] — плохой. */
    const val FAST_ANSWER_MILLIS: Long = 300
    const val SLOW_ANSWER_MILLIS: Long = 1_000
    const val BAD_ANSWER_MILLIS: Long = 3_000

    /** Соединений к одному адресу за пять минут: столько и больше — «часто». */
    const val FREQUENT: Int = 50

    /** Надёжность адреса, %: от [RELIABLE] — хорошо, от [SHAKY] — с перебоями, ниже — плохо. */
    const val RELIABLE: Int = 95
    const val SHAKY: Int = 70

    /** Пороги подсветки скорости, байт/с, и объёма, байт: низкая, средняя, высокая. */
    val RATE_HEAT: LongArray = longArrayOf(16L shl 10, 256L shl 10, 2L shl 20)
    val BYTES_HEAT: LongArray = longArrayOf(1L shl 20, 10L shl 20, 100L shl 20)

    /**
     * Поиск и порядок. [query] — слова через пробел, каждое должно найтись
     * (без учёта регистра) в адресе, имени, назначении, источнике, приложении,
     * протоколе, маршруте, входе, сети или порту; [labels] — подписи оболочки
     * для строки (состояние, маршрут на языке интерфейса), по ним тоже ищется.
     */
    fun view(
        rows: List<ConnectionRow>,
        query: String = "",
        sort: ConnSort = DEFAULT_SORT,
        labels: (ConnectionRow) -> List<String> = { emptyList() },
    ): List<ConnectionRow> = sorted(rows.filter { matches(it, query, labels) }, sort)

    fun matches(row: ConnectionRow, query: String, labels: (ConnectionRow) -> List<String> = { emptyList() }): Boolean {
        val terms = terms(query)
        if (terms.isEmpty()) return true
        val c = row.connection
        val hay = (
            listOf(row.host, c.domain, c.target, c.source, row.app.orEmpty(), c.protocol, c.route, c.inbound, c.network.name, row.port?.toString().orEmpty()) +
                labels(row)
            ).joinToString("\u0000").lowercase(Locale.ROOT)
        return terms.all { it in hay }
    }

    fun sorted(rows: List<ConnectionRow>, sort: ConnSort): List<ConnectionRow> =
        // Равные — новые первыми: порядок не прыгает между снимками.
        rows.sortedWith(order<ConnectionRow>(sort.descending) { key(it, sort.column) }.thenByDescending { it.id })

    /** Ключ сортировки — число ([Long]) или текст; null — значения нет, такие строки всегда внизу. */
    fun key(row: ConnectionRow, column: ConnColumn): Any? {
        val c = row.connection
        return when (column) {
            ConnColumn.STATE -> STATE_ORDER.getValue(c.state)
            ConnColumn.APP -> row.app?.lowercase(Locale.ROOT)
            ConnColumn.HOST -> row.host.lowercase(Locale.ROOT)
            ConnColumn.PORT -> row.port?.toLong()
            ConnColumn.NETWORK -> c.network.name
            ConnColumn.PROTOCOL -> c.protocol.ifEmpty { null }
            // Сначала смысл маршрута (через сервер, напрямую…), внутри — тег.
            ConnColumn.ROUTE -> "${c.routeKind.ordinal}\u0000${c.route}"
            ConnColumn.INBOUND -> "${c.inboundKind.ordinal}\u0000${c.inbound}"
            ConnColumn.DURATION -> c.durationMillis
            ConnColumn.IDLE -> c.idleMillis
            ConnColumn.FIRST_BYTE -> c.firstByteMillis.takeIf { it >= 0 }
            ConnColumn.UP_RATE -> row.upRate
            ConnColumn.DOWN_RATE -> row.downRate
            ConnColumn.UP_BYTES -> c.upBytes
            ConnColumn.DOWN_BYTES -> c.downBytes
            ConnColumn.UP_CHUNKS -> c.upChunks
            ConnColumn.DOWN_CHUNKS -> c.downChunks
            ConnColumn.RECENT -> row.hostRecent.toLong()
            ConnColumn.RELIABILITY -> row.reliability?.toLong()
        }
    }

    /** Порядок по ключу: числа с числами, текст с текстом; без значения — внизу при любом направлении. */
    private fun <T> order(descending: Boolean, key: (T) -> Any?): Comparator<T> = Comparator { a, b ->
        val x = key(a)
        val y = key(b)
        when {
            x == null && y == null -> 0
            x == null -> 1
            y == null -> -1
            else -> {
                val r = when {
                    x is Long && y is Long -> x.compareTo(y)
                    x is String && y is String -> x.compareTo(y)
                    else -> 0
                }
                if (descending) -r else r
            }
        }
    }

    /** Цвет строки: открытые — обычные, закрытые — приглушены, прерванные — тревога. */
    fun rowTone(row: ConnectionRow): Tone = when (row.state) {
        ConnState.OPEN -> Tone.NORMAL
        ConnState.CLOSED -> Tone.MUTED
        ConnState.FAILED -> Tone.BAD
    }

    /** Цвет ячейки: смысл значения в этом столбце. */
    fun tone(row: ConnectionRow, column: ConnColumn): Tone {
        val c = row.connection
        val open = c.state == ConnState.OPEN
        return when (column) {
            ConnColumn.STATE -> when (c.state) {
                ConnState.OPEN -> Tone.GOOD
                ConnState.CLOSED -> Tone.MUTED
                ConnState.FAILED -> Tone.BAD
            }
            ConnColumn.ROUTE -> when (c.routeKind) {
                RouteKind.PROXY, RouteKind.OTHER -> Tone.NORMAL
                RouteKind.DIRECT -> Tone.INFO
                RouteKind.BLOCK -> Tone.WARN
                RouteKind.DNS, RouteKind.NONE -> Tone.MUTED
            }
            ConnColumn.FIRST_BYTE -> when {
                c.firstByteMillis < 0 && open -> if (c.ageMillis >= NO_ANSWER_MILLIS) Tone.WARN else Tone.MUTED
                c.firstByteMillis < 0 -> Tone.BAD
                c.firstByteMillis <= FAST_ANSWER_MILLIS -> Tone.GOOD
                c.firstByteMillis <= SLOW_ANSWER_MILLIS -> Tone.NORMAL
                c.firstByteMillis <= BAD_ANSWER_MILLIS -> Tone.WARN
                else -> Tone.BAD
            }
            ConnColumn.IDLE -> if (open && c.idleMillis >= DORMANT_MILLIS) Tone.MUTED else Tone.NORMAL
            ConnColumn.UP_RATE -> heat(row.upRate, RATE_HEAT)
            ConnColumn.DOWN_RATE -> heat(row.downRate, RATE_HEAT)
            ConnColumn.UP_BYTES -> heat(c.upBytes, BYTES_HEAT)
            ConnColumn.DOWN_BYTES -> heat(c.downBytes, BYTES_HEAT)
            ConnColumn.UP_CHUNKS -> if (c.upChunks == 0L) Tone.MUTED else Tone.NORMAL
            ConnColumn.DOWN_CHUNKS -> if (c.downChunks == 0L) Tone.MUTED else Tone.NORMAL
            ConnColumn.RECENT -> if (row.hostRecent >= FREQUENT) Tone.WARN else Tone.NORMAL
            ConnColumn.RELIABILITY -> when (val r = row.reliability) {
                null -> Tone.MUTED
                in RELIABLE..100 -> Tone.GOOD
                in SHAKY until RELIABLE -> Tone.WARN
                else -> Tone.BAD
            }
            ConnColumn.APP -> if (row.app == null) Tone.MUTED else Tone.NORMAL
            ConnColumn.HOST, ConnColumn.PORT, ConnColumn.NETWORK, ConnColumn.PROTOCOL, ConnColumn.INBOUND, ConnColumn.DURATION -> Tone.NORMAL
        }
    }

    private fun heat(v: Long?, steps: LongArray): Tone = when {
        v == null || v == 0L -> Tone.MUTED
        v >= steps[2] -> Tone.HEAT_HIGH
        v >= steps[1] -> Tone.HEAT_MID
        v >= steps[0] -> Tone.HEAT_LOW
        else -> Tone.NORMAL
    }

    private fun terms(query: String): List<String> = query.lowercase(Locale.ROOT).split(' ', '\t').filter { it.isNotEmpty() }

    private val STATE_ORDER = mapOf(ConnState.OPEN to 0L, ConnState.FAILED to 1L, ConnState.CLOSED to 2L)

    // ---- журнал уникальных ----

    /** Поиск и порядок журнала: последние первыми; [query] — как у [view], по приложению, адресу, порту и сети. */
    fun unique(entries: List<UniqueEntry>, query: String = "", sort: UniqueSort = UniqueSort(UniqueColumn.LAST, descending = true)): List<UniqueEntry> {
        val terms = terms(query)
        val found = if (terms.isEmpty()) {
            entries
        } else {
            entries.filter { e ->
                val hay = listOf(e.key.app.orEmpty(), e.key.host, e.key.port.toString(), e.key.network.name).joinToString("\u0000").lowercase(Locale.ROOT)
                terms.all { it in hay }
            }
        }
        return found.sortedWith(order<UniqueEntry>(sort.descending) { key(it, sort.column) }.thenBy { it.key.host }.thenBy { it.key.port })
    }

    fun key(e: UniqueEntry, column: UniqueColumn): Any? = when (column) {
        UniqueColumn.APP -> e.key.app?.lowercase(Locale.ROOT)
        UniqueColumn.HOST -> e.key.host.lowercase(Locale.ROOT)
        UniqueColumn.PORT -> e.key.port.toLong()
        UniqueColumn.NETWORK -> e.key.network.name
        UniqueColumn.COUNT -> e.count
        UniqueColumn.LAST -> e.lastMillis
    }
}

/** Столбец журнала уникальных соединений (D-106). */
enum class UniqueColumn(val numeric: Boolean) {
    APP(false),
    HOST(false),
    PORT(true),
    NETWORK(false),
    COUNT(true),
    LAST(true),
}

data class UniqueSort(val column: UniqueColumn, val descending: Boolean) {
    fun toggled(c: UniqueColumn): UniqueSort = if (c == column) copy(descending = !descending) else UniqueSort(c, c.numeric)
}
