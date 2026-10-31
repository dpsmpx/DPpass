package com.dpsmpx.dppass.connection

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
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Анализатор соединений (D-106): снимки ядра → таблица, журнал уникальных на диске. */
class AnalyzerTest {
    /** Ядро с учётом соединений: снимок задаёт тест. */
    private class Tracking : ProxyEngine {
        override val capabilities = MockBackend.FULL
        var tracking = false
        var snapshot: EngineConnections? = EngineConnections(enabled = false, skipped = 0, connections = emptyList())

        override suspend fun validate(config: CompiledConfig): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> =
            Outcome.failure(DiagCode.BACKEND_START_FAILED, "не нужен")

        override fun setConnectionTracking(on: Boolean) {
            tracking = on
        }

        override fun connections(): EngineConnections? = snapshot

        fun show(vararg c: EngineConnection, skipped: Long = 0) {
            snapshot = EngineConnections(enabled = tracking, skipped = skipped, connections = c.toList())
        }
    }

    private val clock = ManualClock(1_790_000_000_000)
    private val blobs = InMemoryBlobStore()
    private val engine = Tracking()

    private fun analyzer(max: Int = ConnectionAnalyzer.MAX_UNIQUE) = ConnectionAnalyzer(engine, blobs, Quarantine(blobs, clock), clock, max)

    private fun conn(
        id: Long,
        target: String = "198.51.100.7:443",
        domain: String = "example.com",
        state: ConnState = ConnState.OPEN,
        age: Long = 1_000,
        up: Long = 0,
        down: Long = 0,
        route: RouteKind = RouteKind.PROXY,
        firstByte: Long = 80,
        network: ConnNetwork = ConnNetwork.TCP,
    ) = EngineConnection(
        id = id, network = network, inbound = "tun-in", source = "172.19.0.1:${40_000 + id}", target = target, domain = domain,
        protocol = "tls", route = if (route == RouteKind.NONE) "" else "proxy", state = state, ageMillis = age, durationMillis = age,
        idleMillis = 0, firstByteMillis = firstByte, upBytes = up, downBytes = down, upChunks = if (up > 0) 1 else 0,
        downChunks = if (down > 0) 2 else 0, routeKind = route, inboundKind = InboundKind.TUN,
    )

    @Test
    fun offByDefaultAndTheSettingSurvivesRestart() {
        val a = analyzer()
        assertEquals(AnalyzerSettings(), a.settings())
        a.applyToEngine()
        assertFalse(engine.tracking, "по умолчанию учёта нет — и нагрузки тоже")
        engine.show(conn(1))
        assertTrue(a.poll().rows.isEmpty(), "выключенный анализатор ничего не показывает")

        assertEquals(AnalyzerSettings(enabled = true), a.setEnabled(true).valueOrNull())
        assertTrue(engine.tracking)
        engine.tracking = false
        analyzer().applyToEngine()
        assertTrue(engine.tracking, "настройка — на диске: после перезапуска учёт включается снова")
    }

    @Test
    fun withoutTrackingEngineTheViewSaysUnavailable() {
        val a = analyzer()
        a.setEnabled(true)
        engine.snapshot = null
        val v = a.poll()
        assertFalse(v.available)
        assertTrue(v.rows.isEmpty())
    }

    @Test
    fun ratesComeFromTheDifferenceBetweenSnapshots() {
        val a = analyzer()
        a.setEnabled(true)
        engine.show(conn(1, age = 1_000, up = 1_000, down = 10_000))
        val first = a.poll().rows.single()
        assertNull(first.downRate, "у первого снимка скорости ещё нет")
        assertEquals(clock.nowMillis() - 1_000, first.startedAtMillis)

        clock.advance(2_000)
        engine.show(conn(1, age = 3_000, up = 3_000, down = 1_010_000))
        val second = a.poll()
        assertEquals(1_000, second.rows.single().upRate)
        assertEquals(500_000, second.rows.single().downRate)
        assertEquals(500_000, second.downRate)

        engine.show(conn(1, state = ConnState.CLOSED, age = 4_000, up = 3_000, down = 1_010_000))
        assertNull(a.poll().rows.single().downRate, "у закрытого скорости нет")
    }

    @Test
    fun frequencyAndReliabilityAreCountedPerHost() {
        val a = analyzer()
        a.setEnabled(true)
        engine.show(
            conn(4, target = "198.51.100.9:443", domain = "example.net"),
            conn(3),
            conn(2, state = ConnState.FAILED),
            conn(1, target = "198.51.100.8:443", state = ConnState.CLOSED),
        )
        val rows = a.poll().rows.associateBy { it.id }
        val web = rows.getValue(3)
        assertEquals("example.com", web.host)
        assertEquals(443, web.port)
        assertEquals(3, web.hostRecent, "три соединения к example.com в окне, в том числе к другому адресу")
        assertEquals(2, web.hostFinished)
        assertEquals(50, web.reliability, "одно из двух закончившихся прервано")
        assertNull(rows.getValue(4).reliability, "ни одно не закончилось — надёжность не известна")
    }

    @Test
    fun ownerIsAskedOncePerConnection() {
        val a = analyzer()
        a.setEnabled(true)
        val asked = mutableListOf<Long>()
        val owners = ConnectionOwners { c -> asked += c.id; "org.example.browser" }
        engine.show(conn(1))
        a.poll(owners)
        engine.show(conn(2), conn(1, age = 2_000))
        val rows = a.poll(owners).rows
        assertEquals(listOf(1L, 2L), asked)
        assertTrue(rows.all { it.app == "org.example.browser" })
    }

    @Test
    fun uniqueJournalKeepsOneLinePerConnectionWithCountAndLast() {
        val a = analyzer()
        a.setEnabled(true)
        engine.show(conn(1))
        a.poll()
        assertTrue(a.unique().isEmpty(), "«Сохранять уникальные соединения» выключено — журнал не пополняется")

        a.setKeepUnique(true)
        engine.show(conn(2, route = RouteKind.NONE, domain = ""), conn(1, age = 2_000))
        a.poll()
        assertEquals(listOf(UniqueKey(null, "example.com", 443, ConnNetwork.TCP)), a.unique().map { it.key }, "открытое без маршрута — ещё не известно, куда")

        clock.advance(10_000)
        engine.show(conn(3, age = 500), conn(2, age = 11_000, domain = "example.org"), conn(1, state = ConnState.CLOSED, age = 12_000))
        a.poll()
        val byHost = a.unique().associateBy { it.key.host }
        assertEquals(2, byHost.getValue("example.com").count, "соединения 1 и 3 — одно уникальное, дважды; 1 не посчитано заново")
        assertEquals(clock.nowMillis() - 500, byHost.getValue("example.com").lastMillis)
        assertEquals(1, byHost.getValue("example.org").count, "имя распознано — записано по имени, а не по адресу")
        assertEquals(listOf("example.com", "example.org"), a.unique().map { it.key.host }, "последние первыми")
    }

    @Test
    fun journalIsWrittenAtMostOncePerMinuteAndSurvivesRestart() {
        val a = analyzer()
        a.setEnabled(true)
        a.setKeepUnique(true)
        engine.show(conn(1, target = "[2001:db8::7]:443", domain = "", network = ConnNetwork.UDP))
        a.poll()
        assertTrue(blobs.read(ConnectionAnalyzer.JOURNAL_KEY).valueOrNull() != null, "первая запись — сразу")

        clock.advance(1_000)
        engine.show(
            conn(2, target = "198.51.100.20:53", domain = ""),
            conn(1, age = 2_000, target = "[2001:db8::7]:443", domain = "", network = ConnNetwork.UDP),
        )
        a.poll()
        assertEquals(1, reread().size, "чаще раза в минуту на диск не пишется")
        assertIs<Outcome.Success<Unit>>(a.flush())
        assertEquals(setOf("2001:db8::7", "198.51.100.20"), reread().map { it.key.host }.toSet())
        assertEquals(2, analyzer().unique().size)
    }

    private fun reread(): List<UniqueEntry> =
        UniqueJournalCodec.read(String(blobs.read(ConnectionAnalyzer.JOURNAL_KEY).valueOrNull()!!, Charsets.UTF_8)).valueOrNull()!!

    @Test
    fun clearingTheJournalRemovesItFromDiskAndMemory() {
        val a = analyzer()
        a.setEnabled(true)
        a.setKeepUnique(true)
        engine.show(conn(1))
        a.poll()
        assertIs<Outcome.Success<Unit>>(a.clearJournal())
        assertNull(blobs.read(ConnectionAnalyzer.JOURNAL_KEY).valueOrNull())
        assertTrue(a.unique().isEmpty())
        engine.show(conn(2), conn(1, age = 2_000))
        a.poll()
        assertEquals(1, a.unique().single().count, "после очистки — только новое соединение")
    }

    @Test
    fun turningKeepOffStopsRecordingButKeepsTheJournal() {
        val a = analyzer()
        a.setEnabled(true)
        a.setKeepUnique(true)
        engine.show(conn(1))
        a.poll()
        a.setKeepUnique(false)
        engine.show(conn(2, target = "198.51.100.30:443", domain = "example.net"), conn(1, age = 2_000))
        a.poll()
        assertEquals(listOf("example.com"), a.unique().map { it.key.host })
    }

    @Test
    fun fullJournalSaysSoAndStillCountsKnownLines() {
        val a = analyzer(max = 1)
        a.setEnabled(true)
        a.setKeepUnique(true)
        engine.show(conn(1))
        a.poll()
        engine.show(conn(2, target = "198.51.100.30:443", domain = "example.net"), conn(3), conn(1, age = 2_000))
        val v = a.poll()
        assertTrue(v.journalFull, "журнал полон — сказано, а не молча (D-05)")
        assertEquals(1, v.uniqueCount)
        assertEquals(2, a.unique().single().count)
    }

    @Test
    fun turningOffForgetsWhatWasSeen() {
        val a = analyzer()
        a.setEnabled(true)
        engine.show(conn(1, up = 100))
        a.poll()
        a.setEnabled(false)
        assertFalse(engine.tracking)
        a.setEnabled(true)
        engine.show(conn(1, age = 2_000, up = 1_100))
        assertNull(a.poll().rows.single().upRate, "после выключения прошлый снимок забыт")
    }

    @Test
    fun brokenJournalGoesToQuarantine() {
        blobs.write(ConnectionAnalyzer.JOURNAL_KEY, "{\"format\":\"dppass.connections\",\"format_version\":1,\"entries\":[{}]}".toByteArray())
        val a = analyzer()
        assertTrue(a.unique().isEmpty())
        assertEquals(DiagCode.STORAGE_CORRUPTED, a.loadNotes.single().code)
        assertTrue(blobs.keys("quarantine/connections-").valueOrNull()!!.isNotEmpty())
    }

    @Test
    fun codecsRoundTripAndRefuseWhatTheyDoNotKnow() {
        val entries = listOf(
            UniqueEntry(UniqueKey("org.example.app", "example.com", 443, ConnNetwork.TCP), 3, 1_790_000_000_000),
            UniqueEntry(UniqueKey(null, "198.51.100.53", 53, ConnNetwork.UDP), 1, 1_790_000_000_001),
        )
        assertEquals(entries.toSet(), UniqueJournalCodec.read(UniqueJournalCodec.write(entries)).valueOrNull()!!.toSet())
        val dup = UniqueJournalCodec.write(entries + entries[0].copy(count = 9))
        assertEquals(DiagCode.STORAGE_CORRUPTED, UniqueJournalCodec.read(dup).errors.single().code)
        val extra = UniqueJournalCodec.write(entries).replace("\"count\"", "\"bytes\":1,\"count\"")
        assertEquals(DiagCode.STORAGE_CORRUPTED, UniqueJournalCodec.read(extra).errors.single().code)
        assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, UniqueJournalCodec.read(UniqueJournalCodec.write(entries).replace(":1,", ":2,")).errors.single().code)

        val s = AnalyzerSettings(enabled = true, keepUnique = true)
        assertEquals(s, AnalyzerCodec.read(AnalyzerCodec.write(s)).valueOrNull())
        assertEquals(DiagCode.STORAGE_CORRUPTED, AnalyzerCodec.read(AnalyzerCodec.write(s).replace("true}", "true,\"x\":1}")).errors.single().code)
    }

    @Test
    fun addressAndPortOfTheTarget() {
        assertEquals("example.com" to 443, ConnectionAnalyzer.split(conn(1)))
        assertEquals("2001:db8::7" to 443, ConnectionAnalyzer.split(conn(1, target = "[2001:db8::7]:443", domain = "")))
        assertEquals("198.51.100.7" to null, ConnectionAnalyzer.split(conn(1, target = "198.51.100.7", domain = "")))
    }
}
