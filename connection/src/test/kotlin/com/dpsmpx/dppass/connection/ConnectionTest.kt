package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockBehavior
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.network.LatencyFailure
import com.dpsmpx.dppass.network.LatencyProbe
import com.dpsmpx.dppass.network.LatencyResult
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

internal fun ir(name: String): ConfigIr =
    ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/$name").readText()).valueOrNull()!!.ir

/** Хранилище, чтение из которого можно временно «сломать» (недоступный ключ, сбой ввода-вывода). */
internal class FlakyBlobStore(private val inner: BlobStore) : BlobStore by inner {
    var failReads = false

    override fun read(key: String): Outcome<ByteArray?> =
        if (failReads) Outcome.failure(DiagCode.STORAGE_READ_FAILED, "чтение «$key» временно не работает") else inner.read(key)
}

class ActivationServiceTest {
    private val clock = ManualClock(100)
    private val blobs = InMemoryBlobStore()
    private val engine = MockProxyEngine()
    private fun service() = ActivationService(MockBackendCompiler(), engine, ActivationStore(blobs, Quarantine(blobs, clock)), clock)

    @Test
    fun newConfigBecomesActiveOldBecomesPrevious() = runBlocking {
        val s = service()
        assertIs<ActivationResult.Activated>(s.activate(ir("valid-minimal.json"), "test", "c1"))
        assertIs<ActivationResult.Activated>(s.activate(ir("valid-multi.json"), "test", "c2"))
        assertEquals("c2", s.state.active!!.sourceChecksum)
        assertEquals(ActivationStatus.SUPERSEDED, s.state.previous!!.status)
        assertEquals(6, s.state.activeConfig!!.profiles.size)
    }

    @Test
    fun rejectedConfigLeavesActiveUntouched() = runBlocking {
        val s = service()
        s.activate(ir("valid-minimal.json"), "test", "good")
        engine.behavior = MockBehavior(rejectConfig = true)
        val r = s.activate(ir("valid-multi.json"), "test", "bad")
        val rej = assertIs<ActivationResult.Rejected>(r)
        assertEquals(ActivationStep.BACKEND_VALIDATION, rej.record.failedStep)
        assertEquals(DiagCode.ACTIVATION_REJECTED, rej.diagnostics.first().code)
        assertEquals(DiagCode.BACKEND_REJECTED_CONFIG, rej.diagnostics.first().causes.single().code)
        assertEquals("good", s.state.active!!.sourceChecksum)
        assertEquals(1, s.state.activeConfig!!.profiles.size)
        assertEquals(ActivationStatus.REJECTED, s.state.history.last().status)
    }

    /** Сохраняется только то, что прочитается при следующем запуске (D-07): повтор id — отказ до записи. */
    @Test
    fun configThatWouldNotReloadIsRejectedBeforeCommit() = runBlocking {
        val s = service()
        s.activate(ir("valid-minimal.json"), "test", "good")
        val multi = ir("valid-multi.json")
        val twin = multi.copy(profiles = multi.profiles + multi.profiles.first().copy(name = "двойник"))
        val r = assertIs<ActivationResult.Rejected>(s.activate(twin, "test", "twin"))
        assertEquals(ActivationStep.VALIDATION, r.record.failedStep)
        assertEquals(DiagCode.ID_DUPLICATE, r.diagnostics.first().causes.first().code)
        assertEquals("good", s.state.active!!.sourceChecksum, "действующая конфигурация на месте")
        val again = service()
        assertTrue(again.restore().isEmpty(), "после отказа состояние читается без находок")
    }

    @Test
    fun capabilityRejectionHappensBeforeCompile() = runBlocking {
        val s = ActivationService(
            MockBackendCompiler(MockBackend.LIMITED),
            MockProxyEngine(MockBackend.LIMITED),
            ActivationStore(blobs, Quarantine(blobs, clock)),
            clock,
        )
        val r = s.activate(ir("valid-multi.json"), "test", "x", profileId = ProfileId("hy2"))
        assertEquals(ActivationStep.CAPABILITY, (r as ActivationResult.Rejected).record.failedStep)
        assertNull(s.state.active)
    }

    @Test
    fun failedHealthCheckRejects() = runBlocking {
        val s = service()
        val r = s.activate(ir("valid-minimal.json"), "t", "x", preCheck = { _, _ -> Outcome.failure(DiagCode.PAYLOAD_STALLED, "нет данных") })
        assertEquals(ActivationStep.HEALTH_CHECK, (r as ActivationResult.Rejected).record.failedStep)
    }

    @Test
    fun rollbackRestoresPrevious() = runBlocking {
        val s = service()
        s.activate(ir("valid-minimal.json"), "t", "old")
        s.activate(ir("valid-multi.json"), "t", "new")
        val r = s.rollback(Diagnostic.error(DiagCode.PAYLOAD_STALLED, "в работе данные не идут"))
        assertTrue(r.isSuccess)
        assertEquals("old", s.state.active!!.sourceChecksum)
        assertEquals(1, s.state.activeConfig!!.profiles.size)
        assertEquals(DiagCode.NOTHING_TO_ROLL_BACK, s.rollback(Diagnostic.error(DiagCode.PAYLOAD_STALLED, "x")).errors.single().code)
    }

    @Test
    fun unreadableStateIsNeverOverwritten() = runBlocking {
        val raw = InMemoryBlobStore()
        val flaky = FlakyBlobStore(raw)
        fun on(store: BlobStore) = ActivationService(MockBackendCompiler(), engine, ActivationStore(store, Quarantine(store, clock)), clock)
        on(flaky).activate(ir("valid-multi.json"), "t", "kept")
        val before = raw.rawSnapshot()

        flaky.failReads = true
        val s = on(flaky)
        assertEquals(DiagCode.STORAGE_READ_FAILED, s.restore().single().code)
        // Сохранённое не прочитано: запись затёрла бы действующую и предыдущую конфигурации и историю (D-07).
        val r = assertIs<ActivationResult.Rejected>(s.activate(ir("valid-minimal.json"), "t", "new"))
        assertEquals(ActivationStep.COMMIT, r.record.failedStep)
        assertEquals(DiagCode.STORAGE_READ_FAILED, r.diagnostics.first().causes.single().code)
        assertEquals(DiagCode.STORAGE_READ_FAILED, s.rollback(Diagnostic.error(DiagCode.PAYLOAD_STALLED, "x")).errors.single().causes.single().code)
        assertEquals(before.keys, raw.rawSnapshot().keys)
        before.forEach { (k, v) -> assertTrue(v.contentEquals(raw.rawSnapshot().getValue(k)), "запись $k не должна меняться") }

        // Чтение вернулось: перед записью сервис перечитывает сохранённое и продолжает с него.
        flaky.failReads = false
        assertIs<ActivationResult.Activated>(s.activate(ir("valid-minimal.json"), "t", "new"))
        assertEquals("kept", s.state.previous!!.sourceChecksum)
    }

    @Test
    fun writeWithoutRestoreReadsStoredStateFirst() = runBlocking {
        service().activate(ir("valid-multi.json"), "t", "first")
        val s = service() // restore() не вызывали
        assertIs<ActivationResult.Activated>(s.activate(ir("valid-minimal.json"), "t", "second"))
        assertEquals("first", s.state.previous!!.sourceChecksum, "сохранённая конфигурация — предыдущая, а не затёрта")
    }

    @Test
    fun stateSurvivesRestartAndCorruptionIsQuarantined() = runBlocking {
        val s = service()
        s.activate(ir("valid-multi.json"), "t", "persisted")
        val again = service()
        assertTrue(again.restore().isEmpty())
        assertEquals("persisted", again.state.active!!.sourceChecksum)
        assertEquals(s.state.activeConfig, again.state.activeConfig)

        blobs.write(ActivationStore.KEY, "{not json".toByteArray())
        val broken = service()
        val d = broken.restore()
        assertEquals(DiagCode.STORAGE_CORRUPTED, d.single().code)
        assertNull(broken.state.activeConfig, "повреждённое — не заменяется конфигурацией по умолчанию")
        assertEquals(1, Quarantine(blobs, clock).list().valueOrNull()!!.size)
    }

    /** Повреждение части состояния — находка с местом, а не молчание (D-06, CLAUDE.md «ничего молча»). */
    @Test
    fun partialCorruptionIsReportedNotSilent() = runBlocking {
        val s = service()
        s.activate(ir("valid-multi.json"), "t", "a")
        s.activate(ir("valid-minimal.json"), "t", "b")
        val stored = Json.parse(String(blobs.read(ActivationStore.KEY).valueOrNull()!!)) as JsonObject
        val history = stored["history"] as JsonArray

        // Испорченная запись истории пропускается с находкой; ревизия после неё не повторяется.
        val brokenHistory = JsonArray(history.items + Json.obj("revision" to Json.str("x")))
        blobs.write(ActivationStore.KEY, Json.write(JsonObject(stored.fields + ("history" to brokenHistory) - "next_revision")).toByteArray())
        val again = service()
        val notes = again.restore()
        assertEquals(listOf("$.history[${history.items.size}]", "$.next_revision"), notes.map { it.path }, notes.toString())
        assertTrue(notes.all { it.code == DiagCode.STORAGE_CORRUPTED && !it.isError })
        assertEquals(history.items.size, again.state.history.size)
        assertEquals("b", again.state.active!!.sourceChecksum, "активная конфигурация на месте")
        val latest = (listOfNotNull(again.state.active, again.state.previous) + again.state.history).maxOf { it.revision }
        assertEquals(latest + 1, again.state.nextRevision, "без next_revision счёт — после самой поздней записи, не с 1")

        // Нечитаемая запись об активной конфигурации — состояние не цельное: карантин, а не конфигурация без записи.
        blobs.write(ActivationStore.KEY, Json.write(JsonObject(stored.fields + ("active" to Json.obj("revision" to Json.num(1))))).toByteArray())
        val broken = service()
        val d = broken.restore()
        assertEquals(DiagCode.STORAGE_CORRUPTED, d.single().code)
        assertEquals("$.active", d.single().causes.single().path)
        assertNull(broken.state.activeConfig)
        assertEquals(1, Quarantine(blobs, clock).list().valueOrNull()!!.size)
    }
}

class CandidatePlannerTest {
    private val multi = ir("valid-multi.json")

    private fun assess(c: NetworkCondition) = runBlocking {
        val clock = ManualClock(0)
        NetworkAssessor(SimulatedNetwork(c), ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE)
    }

    private fun plan(c: NetworkCondition?, book: HealthBook = HealthBook(), now: Long = 0, lkg: ProfileId? = null) =
        CandidatePlanner.plan(multi, MockBackend.FULL, c?.let(::assess), book, lkg, now)

    @Test
    fun learnedStabilityOrdersViableCandidates() {
        val assessment = assess(NetworkCondition.NORMAL)
        val context = NetworkContext.of(assessment)
        val good = ProfileId("ss2022")
        val bad = ProfileId("reality-1")
        val model = StabilityModel()
        for (i in 1..12L) {
            model.observe(good, context, StabilityObservation(true, 80, timestampMillis = i * 1_000), multi.profiles.first { it.id == good }, assessment)
            model.observe(bad, context, StabilityObservation(false, 5_000, timestampMillis = i * 1_000), multi.profiles.first { it.id == bad }, assessment)
        }
        // С моделью устойчивый кандидат идёт первым; без неё порядок прежний (по id/приоритету).
        val withModel = CandidatePlanner.plan(multi, MockBackend.FULL, assessment, HealthBook(), null, 0, stability = model)
        val without = CandidatePlanner.plan(multi, MockBackend.FULL, assessment, HealthBook(), null, 0)
        assertEquals(good, withModel.attempts.first().profile.id)
        assertEquals(bad, without.attempts.first().profile.id, "без модели первым — reality-1 (как прежде)")
        // Жёсткие исключения модель не трогает: выбор пользователя всё равно первый.
        val preferredWins = CandidatePlanner.plan(multi, MockBackend.FULL, assessment, HealthBook(), null, 0, preferred = bad, stability = model)
        assertEquals(bad, preferredWins.attempts.first().profile.id, "выбор пользователя (D-34) выше выученной устойчивости")
    }

    @Test
    fun userChoiceGoesFirstAndIgnoresBackoff() {
        val book = HealthBook()
        // ss2022 только что отказал и стоит на паузе; пользователь всё равно выбрал его.
        book.recordFailure(ProfileId("ss2022"), DiagCode.ENDPOINT_UNREACHABLE, 0)
        val auto = plan(NetworkCondition.NORMAL, book, now = 1, lkg = ProfileId("reality-1"))
        assertTrue(auto.excluded.any { it.profileId == ProfileId("ss2022") }, "без выбора — пауза действует")
        val chosen = CandidatePlanner.plan(
            multi, MockBackend.FULL, assess(NetworkCondition.NORMAL), book, ProfileId("reality-1"), 1, preferred = ProfileId("ss2022"),
        )
        assertEquals(ProfileId("ss2022"), chosen.attempts.first().profile.id)
        assertTrue("выбран пользователем" in chosen.attempts.first().reasons)
        // Пауза не истекла — так и сказано, а не «пауза истекла» (журнал 19.10.2026).
        assertTrue("отказывал недавно: пауза ещё 30 с, но выбран пользователем" in chosen.attempts.first().reasons, chosen.attempts.first().reasons.toString())
        assertTrue(chosen.attempts.first().reasons.none { "истекла" in it })
        // Остальные — запасные по D-15: последний удачный среди них, соседние попытки — разных классов.
        val lkg = chosen.attempts.drop(1).single { it.profile.id == ProfileId("reality-1") }
        assertTrue("последний удачный кандидат" in lkg.reasons)
        assertTrue(chosen.attempts[1].profile.transportClass != chosen.attempts[0].profile.transportClass)
        // Исключения по сети действуют и для выбора: UDP не проходит — hy2 не пробуется.
        val udp = CandidatePlanner.plan(
            multi, MockBackend.FULL, assess(NetworkCondition.TCP_REACHABLE_UDP_BLOCKED), HealthBook(), null, 0, preferred = ProfileId("hy2"),
        )
        assertTrue(udp.attempts.none { it.profile.id == ProfileId("hy2") })
    }

    /** D-41: задержка — порядок среди равных по здоровью, классу и приоритету; неизмеренные — после. */
    @Test
    fun latencyOrdersEquallyHealthyCandidates() {
        val v2 = ir("valid-format-v2.json")
        val ms = mapOf(ProfileId("trojan-ios") to 40L, ProfileId("reality-qq") to 180L, ProfileId("ws-edge") to 90L)
        val plan = CandidatePlanner.plan(v2, MockBackend.FULL, null, HealthBook(), null, 0, latency = { ms[it] })
        assertEquals(ProfileId("trojan-ios"), plan.attempts.first().profile.id)
        assertTrue("задержка 40 мс" in plan.attempts.first().reasons)
        val order = plan.attempts.map { it.profile.id }
        // Того же класса (TCP): измеренный reality-qq раньше; HTTP/CDN: измеренный ws-edge раньше неизмеренного xhttp-extra.
        assertTrue(ProfileId("xhttp-extra") !in order || order.indexOf(ProfileId("ws-edge")) < order.indexOf(ProfileId("xhttp-extra")), "$order")
        // Без замеров — прежний порядок по id.
        assertEquals(
            CandidatePlanner.plan(v2, MockBackend.FULL, null, HealthBook(), null, 0).attempts.map { it.profile.id },
            CandidatePlanner.plan(v2, MockBackend.FULL, null, HealthBook(), null, 0, latency = { null }).attempts.map { it.profile.id },
        )
    }

    @Test
    fun deterministicAndBounded() {
        val a = plan(NetworkCondition.NORMAL)
        assertEquals(a, plan(NetworkCondition.NORMAL))
        assertEquals(ConnectionPolicy().maxAttempts, a.attempts.size)
        assertTrue(a.attempts.all { it.reasons.isNotEmpty() })
        assertEquals(multi.profiles.size, a.attempts.size + a.excluded.size)
    }

    @Test
    fun udpBlockedExcludesQuic() {
        val p = plan(NetworkCondition.TCP_REACHABLE_UDP_BLOCKED)
        assertTrue(p.excluded.any { it.profileId == ProfileId("hy2") && "UDP" in it.reason })
    }

    @Test
    fun allowlistKeepsOnlyMarkedCandidates() {
        val p = plan(NetworkCondition.ALLOWLIST_LIKE)
        assertEquals(listOf(ProfileId("domestic-relay")), p.attempts.map { it.profile.id })
    }

    @Test
    fun allowlistWithoutReachableCandidateExplainsLimit() {
        val noRelay = multi.copy(profiles = multi.profiles.filter { !it.hints.reachableUnderAllowlist })
        val clock = ManualClock(0)
        val x = runBlocking {
            NetworkAssessor(SimulatedNetwork(NetworkCondition.ALLOWLIST_LIKE), ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE)
        }
        val p = CandidatePlanner.plan(noRelay, MockBackend.FULL, x, HealthBook(), null, 0)
        assertTrue(p.attempts.isEmpty())
        assertEquals(DiagCode.NO_VIABLE_CANDIDATE, p.verdict)
        assertTrue("D-13" in p.verdictMessage!!)
    }

    @Test
    fun offlineAndCaptiveMakeNoAttempts() {
        assertEquals(DiagCode.NETWORK_OFFLINE, plan(NetworkCondition.OFFLINE).verdict)
        assertTrue(plan(NetworkCondition.CAPTIVE_PORTAL).attempts.isEmpty())
    }

    @Test
    fun degradedTlsPutsOtherClassesFirst() {
        assertEquals(ProfileId("xhttp-cdn"), plan(NetworkCondition.TLS_DEGRADED).attempts.first().profile.id)
    }

    @Test
    fun backoffExcludesUntilItExpires() {
        val book = HealthBook()
        book.recordFailure(ProfileId("reality-1"), DiagCode.PAYLOAD_STALLED, now = 0)
        assertTrue(plan(NetworkCondition.NORMAL, book, now = 1_000).excluded.any { it.profileId == ProfileId("reality-1") && "пауза" in it.reason })
        // пауза истекла: кандидат снова допускается, но как отказывавший — в конец очереди
        val after = plan(NetworkCondition.NORMAL, book, now = 31_000)
        assertTrue(after.excluded.none { it.profileId == ProfileId("reality-1") && "пауза" in it.reason })
        assertTrue(after.attempts.none { it.profile.id == ProfileId("reality-1") } || after.attempts.last().profile.id == ProfileId("reality-1"))
        book.recordFailure(ProfileId("reality-1"), DiagCode.PAYLOAD_STALLED, now = 31_000)
        assertTrue(plan(NetworkCondition.NORMAL, book, now = 61_000).excluded.any { it.profileId == ProfileId("reality-1") }, "второй отказ — пауза вдвое")
    }

    @Test
    fun lastKnownGoodCandidateGoesFirst() {
        assertEquals(ProfileId("trojan-ws"), plan(NetworkCondition.NORMAL, lkg = ProfileId("trojan-ws")).attempts.first().profile.id)
    }
}

class OrchestratorTest {
    private fun run(c: NetworkCondition): Pair<ConnectionReport, MockProxyEngine> = runBlocking {
        val clock = ManualClock(0)
        val multi = ir("valid-multi.json")
        val net = SimulatedNetwork(c, setOf("203.0.113.10:443"))
        val x = NetworkAssessor(net, ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE)
        val book = HealthBook()
        val plan = CandidatePlanner.plan(multi, MockBackend.FULL, x, book, null, clock.nowMillis())
        val engine = MockProxyEngine()
        val pauses = mutableListOf<Long>()
        val log = com.dpsmpx.dppass.diagnostics.Logger("t", com.dpsmpx.dppass.diagnostics.MemoryLogSink(), clock::nowMillis)
        val report = ConnectionOrchestrator(MockBackendCompiler(), engine, SimulatedHealthChecker(net), book, clock, log) { pauses += it; clock.advance(it) }
            .connect(multi, plan, null)
        assertEquals((report.attempts.size - 1).coerceAtLeast(0), pauses.size, "пауза между каждой парой попыток")
        report to engine
    }

    @Test
    fun fallsBackFromBlockedIpToNextCandidate() {
        val (r, _) = run(NetworkCondition.IP_BLOCKED)
        val connected = assertIs<ConnectionReport.Connected>(r)
        assertEquals(ProfileId("reality-1"), r.attempts.first().profileId)
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, r.attempts.first().failure!!.code)
        assertEquals(ProfileId("xhttp-cdn"), connected.profileId)
    }

    @Test
    fun stalledPayloadCountsAsFailure() {
        val (r, _) = run(NetworkCondition.PACKET_LOSS)
        assertIs<ConnectionReport.Connected>(r)
        assertTrue(r.attempts.any { it.failure?.code == DiagCode.PAYLOAD_STALLED })
    }

    @Test
    fun exhaustsBoundedAttemptsAndStopsEachSession() {
        val (r, engine) = run(NetworkCondition.FULL_ENDPOINT_BLOCK)
        val failed = assertIs<ConnectionReport.Failed>(r)
        assertEquals(DiagCode.ATTEMPTS_EXHAUSTED, failed.reason.code)
        assertEquals(ConnectionPolicy().maxAttempts, r.attempts.size)
        assertNull(engine.runningSession(), "неудачные сессии остановлены")
    }

    /**
     * Отмена посреди проверки здоровья («Отключить», onRevoke, переподключение)
     * останавливает уже запущенное ядро: иначе оно работало бы без TUN, а с
     * раздачей (D-51) — с открытым прокси, и следующий запуск упирался бы в
     * BACKEND_ALREADY_RUNNING, наказывая серверы.
     */
    @Test
    fun cancelDuringHealthCheckStopsTheStartedCore() = runBlocking {
        val clock = ManualClock(0)
        val multi = ir("valid-multi.json")
        val book = HealthBook()
        val plan = CandidatePlanner.plan(multi, MockBackend.FULL, null, book, null, 0)
        val engine = MockProxyEngine()
        val log = Logger("t", MemoryLogSink(), clock::nowMillis)
        val inCheck = CompletableDeferred<Unit>()
        val hanging = HealthChecker { _, _ ->
            inCheck.complete(Unit)
            awaitCancellation()
        }
        val job = launch { ConnectionOrchestrator(MockBackendCompiler(), engine, hanging, book, clock, log) { clock.advance(it) }.connect(multi, plan, null) }
        inCheck.await()
        assertNotNull(engine.runningSession(), "ядро запущено, идёт проверка здоровья")
        job.cancelAndJoin()
        assertNull(engine.runningSession(), "отмена остановила запущенное ядро")
        val again = ConnectionOrchestrator(MockBackendCompiler(), engine, { _, _ -> Outcome.Success(Unit) }, book, clock, log) { clock.advance(it) }
            .connect(multi, plan, null)
        assertIs<ConnectionReport.Connected>(again)
        assertTrue(again.attempts.none { it.failure?.code == DiagCode.BACKEND_ALREADY_RUNNING }, again.attempts.toString())
    }

    /** Ядро, у которого вход раздачи не встаёт (адрес пропал, порт занят): запуск с входами раздачи — отказ. */
    private class ShareCannotBind : ProxyEngine {
        override val capabilities = XrayBackend.CAPABILITIES
        val starts = mutableListOf<Boolean>()
        private var running: EngineSession? = null

        override suspend fun validate(config: CompiledConfig): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> {
            val withShare = "\"${XrayBackend.SHARE_TAG_PREFIX}0\"" in config.payloadForEngine()
            starts += withShare
            if (running != null) return Outcome.failure(DiagCode.BACKEND_ALREADY_RUNNING, "ядро уже запущено")
            if (withShare) return Outcome.failure(DiagCode.BACKEND_START_FAILED, "listen tcp 192.168.43.1:41234: bind: cannot assign requested address")
            val s = object : EngineSession {
                private var state = EngineState.RUNNING
                override val compiled = config

                override fun state() = state

                override fun stats() = TrafficStats(0, 0)

                override suspend fun stop() {
                    state = EngineState.STOPPED
                    running = null
                }
            }
            running = s
            return Outcome.Success(s)
        }
    }

    /** D-51: вход раздачи не встал — туннель без раздачи, а сервер не наказан за чужой отказ. */
    @Test
    fun shareThatCannotBindIsDroppedWithoutBlamingServers() = runBlocking {
        val clock = ManualClock(0)
        val multi = ir("valid-multi.json")
        val book = HealthBook()
        val plan = CandidatePlanner.plan(multi, XrayBackend.CAPABILITIES, null, book, null, 0)
        val engine = ShareCannotBind()
        val share = ShareSpec(listOf(ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24)), 41234, Secret("u-test"), Secret("p-test-0123456789"))
        var checks = 0
        // Первый кандидат не проходит проверку здоровья — второй пробуется уже без раздачи.
        val health = HealthChecker { _, _ ->
            if (checks++ == 0) Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "сервер недоступен") else Outcome.Success(Unit)
        }
        val log = Logger("t", MemoryLogSink(), clock::nowMillis)
        val report = ConnectionOrchestrator(XrayCompiler(), engine, health, book, clock, log) { clock.advance(it) }.connect(multi, plan, null, share)
        val connected = assertIs<ConnectionReport.Connected>(report)
        assertEquals(DiagCode.BACKEND_START_FAILED, connected.shareRefused?.code)
        assertEquals(listOf(true, false, false), engine.starts, "с раздачей — один запуск; повтор той же попытки и следующая — без неё")
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, report.attempts.first().failure?.code, "первый отказ — от проверки здоровья")
        assertTrue(report.attempts.none { it.failure?.code == DiagCode.BACKEND_START_FAILED }, "отказ входа раздачи не записан серверу")
    }

    @Test
    fun emptyPlanFailsWithVerdict() {
        val (r, engine) = run(NetworkCondition.OFFLINE)
        assertEquals(DiagCode.NETWORK_OFFLINE, assertIs<ConnectionReport.Failed>(r).reason.code)
        assertTrue(engine.startedProfiles.isEmpty())
        assertNotNull(r.plan.verdictMessage)
    }
}

class LatencyBookTest {
    @Test
    fun measuresTcpOneByOneAndSkipsUdp() = runBlocking {
        val v2 = ir("valid-format-v2.json")
        val probed = mutableListOf<String>()
        val pauses = mutableListOf<Long>()
        val probe = LatencyProbe { host, port, _ ->
            probed += "$host:$port"
            if (port == 443 && host.toString() == "203.0.113.26") LatencyResult.Failed(LatencyFailure.TIMEOUT) else LatencyResult.Measured(42)
        }
        val book = LatencyBook()
        val seen = mutableListOf<ProfileId>()
        book.measureAll(v2.profiles, probe, { pauses += it }) { id, _ -> seen += id }
        assertEquals(v2.profiles.map { it.id }, seen)
        assertEquals(LatencyResult.NotTcp, book.of(ProfileId("hy2-bbr")))
        assertTrue(probed.none { it.startsWith("192.0.2.30") }, "UDP не мерится TCP")
        assertEquals(LatencyResult.Failed(LatencyFailure.TIMEOUT), book.of(ProfileId("xhttp-extra")))
        assertNull(book.millis(ProfileId("xhttp-extra")), "тайм-аут — не задержка")
        assertEquals(42L, book.millis(ProfileId("trojan-ios")))
        assertTrue(pauses.isNotEmpty() && pauses.all { it == LatencyBook.PACING_MILLIS }, "по одному, с паузой")
    }
}
