package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import com.dpsmpx.dppass.engine.RouteKind
import java.util.Locale
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Текст ячеек анализатора (D-106): одна логика на телефоне и ПК. */
class ConnectionCellsTest {
    private val l = CellLabels(
        open = "Открыто", closed = "Закрыто", failed = "Прервано",
        routeProxy = "Сервер", routeDirect = "Напрямую", routeBlock = "Блок", routeDns = "DNS",
        inTun = "VPN", inLocal = "Без VPN", inShare = "Раздача", inSelf = "DPpass",
        noAnswer = "нет ответа", ms = "мс", s = "с", percent = "%d %%", locale = Locale.forLanguageTag("ru"),
        bytes = { "$it Б" }, speed = { "$it Б/с" },
    )

    private fun row(
        state: ConnState = ConnState.OPEN,
        firstByte: Long = 120,
        age: Long = 1_000,
        duration: Long = 65_000,
        route: RouteKind = RouteKind.PROXY,
        tag: String = "proxy",
        inbound: InboundKind = InboundKind.TUN,
        inboundTag: String = "tun-in",
        finished: Int = 0,
        failed: Int = 0,
        app: String? = "org.example.browser",
    ) = ConnectionRow(
        EngineConnection(
            id = 1, network = ConnNetwork.TCP, inbound = inboundTag, source = "172.19.0.1:40000", target = "198.51.100.7:443",
            domain = "example.com", protocol = "", route = tag, state = state, ageMillis = age, durationMillis = duration, idleMillis = 3_723_000,
            firstByteMillis = firstByte, upBytes = 517, downBytes = 3_000, upChunks = 1_234_567, downChunks = 3,
            routeKind = route, inboundKind = inbound,
        ),
        app, "example.com", 443, 0, null, 2_048, 3, finished, failed,
    )

    private fun cell(r: ConnectionRow, c: ConnColumn) = ConnectionCells.text(r, c, l) { "Браузер" }

    @Test
    fun cellsReadLikeAStrictTable() {
        val r = row()
        assertEquals("Открыто", cell(r, ConnColumn.STATE))
        assertEquals("Браузер", cell(r, ConnColumn.APP), "приложение — подписью оболочки")
        assertEquals("—", cell(row(app = null), ConnColumn.APP))
        assertEquals("—", cell(r, ConnColumn.PROTOCOL), "не распознано — прочерк")
        assertEquals("1:05", cell(r, ConnColumn.DURATION))
        assertEquals("1:02:03", cell(r, ConnColumn.IDLE))
        assertEquals("45 с", ConnectionCells.duration(45_400, l))
        assertEquals("120 мс", cell(r, ConnColumn.FIRST_BYTE))
        assertEquals("1,5 с", ConnectionCells.latency(1_500, l))
        assertEquals("—", cell(r, ConnColumn.UP_RATE), "скорости ещё нет")
        assertEquals("2048 Б/с", cell(r, ConnColumn.DOWN_RATE))
        assertEquals("517 Б", cell(r, ConnColumn.UP_BYTES))
        assertTrue(cell(r, ConnColumn.UP_CHUNKS).replace(' ', ' ') == "1 234 567", "порции — с разрядами: ${cell(r, ConnColumn.UP_CHUNKS)}")
        assertEquals("—", cell(r, ConnColumn.RELIABILITY))
        assertEquals("66 %", cell(row(finished = 3, failed = 1), ConnColumn.RELIABILITY), "вниз: надёжность не завышается")
    }

    @Test
    fun answerRouteAndInboundSayWhatTheyMean() {
        assertEquals("—", cell(row(firstByte = -1, age = 1_000), ConnColumn.FIRST_BYTE), "ответа ещё ждём")
        assertEquals("нет ответа", cell(row(firstByte = -1, age = 6_000), ConnColumn.FIRST_BYTE))
        assertEquals("нет ответа", cell(row(firstByte = -1, state = ConnState.FAILED), ConnColumn.FIRST_BYTE))
        assertEquals("Напрямую", cell(row(route = RouteKind.DIRECT, tag = "direct"), ConnColumn.ROUTE))
        assertEquals("relay-1", cell(row(route = RouteKind.OTHER, tag = "relay-1"), ConnColumn.ROUTE), "иной исходящий — своим тегом")
        assertEquals("Раздача", cell(row(inbound = InboundKind.SHARE, inboundTag = "dppass:share-0"), ConnColumn.INBOUND))
        assertEquals("DPpass", cell(row(inbound = InboundKind.OTHER, inboundTag = ""), ConnColumn.INBOUND), "свои запросы DPpass")
        assertEquals(listOf("Прервано", "Сервер", "VPN", "Браузер"), ConnectionCells.searchLabels(row(state = ConnState.FAILED), l) { "Браузер" })
    }

    @Test
    fun samplesAreAtLeastAsWideAsValues() {
        for (c in ConnColumn.entries) {
            val sample = ConnectionCells.sample(c, l)
            assertTrue(sample.isNotEmpty(), "у столбца $c нет образца")
        }
        assertEquals("Прервано", ConnectionCells.sample(ConnColumn.STATE, l))
        assertEquals("нет ответа", ConnectionCells.sample(ConnColumn.FIRST_BYTE, l))
        val e = UniqueEntry(UniqueKey(null, "example.com", 443, ConnNetwork.UDP), 12_345, 0)
        assertEquals("UDP", ConnectionCells.unique(e, UniqueColumn.NETWORK, l, { "дата" }))
        assertEquals("дата", ConnectionCells.unique(e, UniqueColumn.LAST, l, { "дата" }))
        assertEquals("—", ConnectionCells.unique(e, UniqueColumn.APP, l, { "дата" }))
    }
}
