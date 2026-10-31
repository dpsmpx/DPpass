package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.ConnColumn
import com.dpsmpx.dppass.connection.ConnectionAnalyzer
import com.dpsmpx.dppass.connection.ConnectionOwners
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.EngineConnections
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.InboundKind
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.RouteKind
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import javax.swing.JLabel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Окно «Соединения» на ПК (D-106): таблица, порядок по заголовку, поиск, цвета, журнал. Данные синтетические. */
class ConnectionsPanelTest {
    private class Tracking : ProxyEngine {
        override val capabilities = XrayBackend.CAPABILITIES
        var tracking = false
        var rows: List<EngineConnection> = emptyList()

        override suspend fun validate(config: CompiledConfig): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> =
            Outcome.failure(DiagCode.BACKEND_START_FAILED, "не нужен")

        override fun setConnectionTracking(on: Boolean) {
            tracking = on
        }

        override fun connections(): EngineConnections = EngineConnections(tracking, 0, rows)
    }

    private fun conn(id: Long, domain: String, state: ConnState = ConnState.OPEN, age: Long = 1_000, down: Long = 0) = EngineConnection(
        id = id, network = ConnNetwork.TCP, inbound = "tun-in", source = "172.19.0.1:${40_000 + id}", target = "198.51.100.$id:443",
        domain = domain, protocol = "tls", route = "proxy", state = state, ageMillis = age, durationMillis = age, idleMillis = 0,
        firstByteMillis = 50, upBytes = 0, downBytes = down, upChunks = 0, downChunks = 0, routeKind = RouteKind.PROXY, inboundKind = InboundKind.TUN,
    )

    private val clock = ManualClock(1_790_000_000_000)
    private val blobs = InMemoryBlobStore()
    private val engine = Tracking()
    private val analyzer = ConnectionAnalyzer(engine, blobs, Quarantine(blobs, clock), clock)
    private val owners = ConnectionOwners { "firefox" }
    private val panel = ConnectionsPanel(analyzer, owners, CoroutineScope(Dispatchers.Unconfined))

    private fun column(c: ConnColumn) = ConnectionsPanel.LIVE.indexOf(c)

    private fun cells(c: ConnColumn): List<String> = (0 until panel.table.rowCount).map { panel.table.getValueAt(it, column(c)).toString() }

    @Test
    fun tableShowsConnectionsSortedLikeTopAndByHeader() = runBlocking {
        analyzer.setEnabled(true)
        engine.rows = listOf(conn(3, "c.example"), conn(2, "a.example", state = ConnState.FAILED), conn(1, "b.example", state = ConnState.CLOSED))
        panel.refresh()
        engine.rows = listOf(
            conn(3, "c.example", age = 2_000, down = 3L shl 20),
            conn(2, "a.example", state = ConnState.FAILED, age = 2_000),
            conn(1, "b.example", state = ConnState.CLOSED, age = 2_000),
        )
        clock.advance(1_000)
        panel.refresh()
        assertEquals(listOf("c.example", "a.example", "b.example"), cells(ConnColumn.HOST), "сверху — кто больше получает, как в top")
        assertEquals("firefox", cells(ConnColumn.APP).first(), "процесс у соединения")
        assertTrue(panel.table.getColumnName(column(ConnColumn.DOWN_RATE)).endsWith("▼"), "стрелка у столбца сортировки")

        panel.headerClicked(column(ConnColumn.HOST))
        assertEquals(listOf("a.example", "b.example", "c.example"), cells(ConnColumn.HOST), "заголовок «Адрес» — по алфавиту")
        panel.headerClicked(column(ConnColumn.HOST))
        assertEquals(listOf("c.example", "b.example", "a.example"), cells(ConnColumn.HOST), "второе нажатие — обратно")

        panel.search.text = "Прервано"
        assertEquals(listOf("a.example"), cells(ConnColumn.HOST), "поиск по подписям ячеек")
        panel.search.text = ""
    }

    @Test
    fun colorsMeanStateAndHeat() = runBlocking {
        analyzer.setEnabled(true)
        engine.rows = listOf(conn(2, "a.example", state = ConnState.FAILED), conn(1, "b.example", age = 1_000))
        panel.refresh()
        engine.rows = listOf(conn(2, "a.example", state = ConnState.FAILED, age = 2_000), conn(1, "b.example", age = 2_000, down = 3L shl 20))
        clock.advance(1_000)
        panel.refresh()
        val t = panel.table
        fun rendered(row: Int, c: ConnColumn) = t.prepareRenderer(t.getCellRenderer(row, column(c)), row, column(c)) as JLabel
        val failed = cells(ConnColumn.HOST).indexOf("a.example")
        val busy = cells(ConnColumn.HOST).indexOf("b.example")
        assertEquals(Theme.palette.error, rendered(failed, ConnColumn.STATE).foreground, "прервано — цветом ошибки")
        assertEquals(Theme.palette.success, rendered(busy, ConnColumn.STATE).foreground, "открыто — цветом успеха")
        assertEquals(Theme.palette.primaryContainer, rendered(busy, ConnColumn.DOWN_RATE).background, "3 МиБ/с — самая плотная подсветка")
        assertEquals(javax.swing.SwingConstants.RIGHT, rendered(busy, ConnColumn.DOWN_BYTES).horizontalAlignment, "числа — вправо")
    }

    @Test
    fun journalTabShowsUniqueConnectionsAndClearEmptiesIt() = runBlocking {
        analyzer.setEnabled(true)
        analyzer.setKeepUnique(true)
        engine.rows = listOf(conn(1, "a.example"))
        panel.refresh()
        panel.journalTab.doClick()
        assertEquals(1, panel.table.rowCount)
        assertEquals("a.example", panel.table.getValueAt(0, ConnectionsPanel.UNIQUE.indexOf(com.dpsmpx.dppass.connection.UniqueColumn.HOST)))
        assertEquals("Строк в журнале: 1", panel.status.text)
        analyzer.clearJournal()
        panel.render()
        assertEquals(0, panel.table.rowCount)
        assertEquals("Журнал пуст.", panel.status.text)
    }

    @Test
    fun offSaysHowToTurnOn() = runBlocking {
        panel.refresh()
        assertEquals(0, panel.table.rowCount)
        assertTrue("Включите анализатор" in panel.status.text, panel.status.text)
    }
}
