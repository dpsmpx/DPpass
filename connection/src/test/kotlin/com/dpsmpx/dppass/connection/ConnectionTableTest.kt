package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import com.dpsmpx.dppass.engine.RouteKind
import kotlin.test.Test
import kotlin.test.assertEquals

/** Таблица анализатора (D-106): порядок, поиск и цвета — одни на телефоне и ПК. */
class ConnectionTableTest {
    private fun row(
        id: Long,
        host: String = "example.com",
        state: ConnState = ConnState.OPEN,
        downRate: Long? = null,
        down: Long = 0,
        firstByte: Long = 80,
        age: Long = 1_000,
        route: RouteKind = RouteKind.PROXY,
        app: String? = null,
        recent: Int = 1,
        finished: Int = 0,
        failed: Int = 0,
    ) = ConnectionRow(
        EngineConnection(
            id = id, network = ConnNetwork.TCP, inbound = "tun-in", source = "172.19.0.1:40000", target = "198.51.100.7:443", domain = host,
            protocol = "tls", route = "proxy", state = state, ageMillis = age, durationMillis = age, idleMillis = 0, firstByteMillis = firstByte,
            upBytes = 0, downBytes = down, upChunks = 0, downChunks = 0, routeKind = route, inboundKind = InboundKind.TUN,
        ),
        app, host, 443, 0, null, downRate, recent, finished, failed,
    )

    @Test
    fun defaultOrderIsLikeTopAndRowsWithoutValueStayAtTheBottom() {
        val rows = listOf(row(1, downRate = 10), row(2, downRate = null), row(3, downRate = 5_000), row(4, downRate = 10))
        assertEquals(listOf(3L, 4L, 1L, 2L), ConnectionTable.view(rows).map { it.id }, "больше получает — выше; равные — новые первыми")
        val up = ConnectionTable.sorted(rows, ConnSort(ConnColumn.DOWN_RATE, descending = false))
        assertEquals(listOf(4L, 1L, 3L, 2L), up.map { it.id }, "без значения — внизу и при обратном порядке")
    }

    @Test
    fun headerClickFlipsOrChoosesTheNaturalDirection() {
        val s = ConnectionTable.DEFAULT_SORT
        assertEquals(ConnSort(ConnColumn.DOWN_RATE, descending = false), s.toggled(ConnColumn.DOWN_RATE))
        assertEquals(ConnSort(ConnColumn.HOST, descending = false), s.toggled(ConnColumn.HOST), "текст — по алфавиту")
        assertEquals(ConnSort(ConnColumn.UP_BYTES, descending = true), s.toggled(ConnColumn.UP_BYTES), "число — сначала большие")
    }

    @Test
    fun sortByStateTextAndReliability() {
        val rows = listOf(
            row(1, host = "b.example", state = ConnState.CLOSED, finished = 2),
            row(2, host = "A.example", state = ConnState.FAILED, finished = 2, failed = 2),
            row(3, host = "c.example", finished = 0),
        )
        assertEquals(listOf(3L, 2L, 1L), ConnectionTable.sorted(rows, ConnSort(ConnColumn.STATE, false)).map { it.id }, "открытые, прерванные, закрытые")
        assertEquals(listOf(2L, 1L, 3L), ConnectionTable.sorted(rows, ConnSort(ConnColumn.HOST, false)).map { it.id }, "без учёта регистра")
        val byReliability = ConnectionTable.sorted(rows, ConnSort(ConnColumn.RELIABILITY, false)).map { it.id }
        assertEquals(listOf(2L, 1L, 3L), byReliability, "худшие сверху, неизвестная — внизу")
    }

    @Test
    fun searchNeedsEveryWordAnywhereInTheRow() {
        val rows = listOf(
            row(1, host = "video.example.com", app = "org.example.player"),
            row(2, host = "mail.example.net"),
            row(3, host = "example.org", state = ConnState.FAILED),
        )
        assertEquals(listOf(1L), ConnectionTable.view(rows, "EXAMPLE player").map { it.id })
        val byHost = ConnectionTable.view(rows, "  443 tcp ", ConnSort(ConnColumn.HOST, true)).map { it.id }
        assertEquals(listOf(1L, 2L, 3L), byHost, "video, mail, example — по убыванию")
        val labels = { r: ConnectionRow -> listOf(if (r.state == ConnState.FAILED) "Ошибка" else "Открыто") }
        assertEquals(listOf(3L), ConnectionTable.view(rows, "ошибка", labels = labels).map { it.id }, "и по подписям оболочки")
        assertEquals(emptyList(), ConnectionTable.view(rows, "example.com mail").map { it.id })
    }

    @Test
    fun tonesMeanStateAnswerAndHeat() {
        assertEquals(Tone.GOOD, ConnectionTable.tone(row(1), ConnColumn.STATE))
        assertEquals(Tone.BAD, ConnectionTable.tone(row(1, state = ConnState.FAILED), ConnColumn.STATE))
        assertEquals(Tone.MUTED, ConnectionTable.rowTone(row(1, state = ConnState.CLOSED)))

        assertEquals(Tone.GOOD, ConnectionTable.tone(row(1, firstByte = 80), ConnColumn.FIRST_BYTE))
        assertEquals(Tone.WARN, ConnectionTable.tone(row(1, firstByte = 2_000), ConnColumn.FIRST_BYTE))
        assertEquals(Tone.BAD, ConnectionTable.tone(row(1, firstByte = 4_000), ConnColumn.FIRST_BYTE))
        assertEquals(Tone.MUTED, ConnectionTable.tone(row(1, firstByte = -1, age = 1_000), ConnColumn.FIRST_BYTE), "ответа ждём")
        assertEquals(Tone.WARN, ConnectionTable.tone(row(1, firstByte = -1, age = 6_000), ConnColumn.FIRST_BYTE), "нет ответа")
        assertEquals(Tone.BAD, ConnectionTable.tone(row(1, firstByte = -1, state = ConnState.CLOSED), ConnColumn.FIRST_BYTE), "закрылось без ответа")

        assertEquals(Tone.INFO, ConnectionTable.tone(row(1, route = RouteKind.DIRECT), ConnColumn.ROUTE))
        assertEquals(Tone.WARN, ConnectionTable.tone(row(1, route = RouteKind.BLOCK), ConnColumn.ROUTE))

        assertEquals(Tone.MUTED, ConnectionTable.tone(row(1, downRate = 0), ConnColumn.DOWN_RATE))
        assertEquals(Tone.HEAT_LOW, ConnectionTable.tone(row(1, downRate = 20_000), ConnColumn.DOWN_RATE))
        assertEquals(Tone.HEAT_HIGH, ConnectionTable.tone(row(1, downRate = 3L shl 20), ConnColumn.DOWN_RATE))
        assertEquals(Tone.HEAT_MID, ConnectionTable.tone(row(1, down = 20L shl 20), ConnColumn.DOWN_BYTES))

        assertEquals(Tone.GOOD, ConnectionTable.tone(row(1, finished = 20, failed = 0), ConnColumn.RELIABILITY))
        assertEquals(Tone.WARN, ConnectionTable.tone(row(1, finished = 10, failed = 2), ConnColumn.RELIABILITY))
        assertEquals(Tone.BAD, ConnectionTable.tone(row(1, finished = 2, failed = 2), ConnColumn.RELIABILITY))
        assertEquals(Tone.WARN, ConnectionTable.tone(row(1, recent = 60), ConnColumn.RECENT), "частые соединения к одному адресу")
        assertEquals(Tone.MUTED, ConnectionTable.tone(row(1), ConnColumn.APP), "приложение не узнать")
    }

    @Test
    fun uniqueJournalIsSearchableAndSortable() {
        val e = listOf(
            UniqueEntry(UniqueKey("org.example.app", "example.com", 443, ConnNetwork.TCP), 5, 300),
            UniqueEntry(UniqueKey(null, "198.51.100.53", 53, ConnNetwork.UDP), 50, 100),
            UniqueEntry(UniqueKey(null, "example.net", 443, ConnNetwork.TCP), 1, 200),
        )
        assertEquals(listOf("example.com", "example.net", "198.51.100.53"), ConnectionTable.unique(e).map { it.key.host }, "последние первыми")
        assertEquals(listOf("198.51.100.53"), ConnectionTable.unique(e, "udp").map { it.key.host })
        assertEquals(listOf(50L, 5L, 1L), ConnectionTable.unique(e, sort = UniqueSort(UniqueColumn.COUNT, true)).map { it.count })
        val byApp = ConnectionTable.unique(e, sort = UniqueSort(UniqueColumn.APP, false)).map { it.key.host }
        assertEquals(listOf("example.com", "198.51.100.53", "example.net"), byApp, "без приложения — внизу")
    }
}
