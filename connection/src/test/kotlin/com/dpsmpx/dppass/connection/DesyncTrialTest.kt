package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.LogHistory
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.DesyncCounters
import com.dpsmpx.dppass.engine.DesyncTrick
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Замер А/Б эксперимента (D-116, FAKE_PACKETS.md, §6.2): каждый вариант
 * поровну и вперемешку, пауза между попытками, приём сверяется по счётчикам
 * моста, без TLS поверх TCP — отказ до первой попытки.
 */
class DesyncTrialTest {
    private val clock = ManualClock(1_000)
    private val engine = MockProxyEngine()
    private val core = DPpassCore(MockBackendCompiler(), engine, InMemoryBlobStore(), clock, "com.dpsmpx.dppass", PlatformTraits(true))

    /** Компилятор, который запоминает план попытки; [noTls] — сервер без TLS поверх TCP, как у XrayCompiler. */
    private inner class Recording(private val noTls: Boolean = false) : BackendCompiler by MockBackendCompiler() {
        var last: CompilePlan? = null
        val plans = mutableListOf<CompilePlan>()

        override fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig> {
            last = plan
            plans += plan
            val r = MockBackendCompiler().compile(ir, plan.copy(desync = null))
            if (noTls && plan.desync != null && r is Outcome.Success) {
                return Outcome.Success(r.value, r.diagnostics + Diagnostic.warning(DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED, "нет TLS поверх TCP"))
            }
            return r
        }
    }

    private fun ir(): ConfigIr = runBlocking {
        core.load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()).valueOrNull()!!.ir
    }

    @Test
    fun everyVariantEquallyOftenAndShuffled() {
        val settings = TrialSettings(ttlFrom = 3, ttlTo = 5, attempts = 10)
        val trial = DesyncTrial(Recording(), engine, clock, core.log, java.util.Random(7)::nextInt)
        val order = trial.schedule(settings)
        assertEquals(listOf("plain", "split", "disorder", "fake-3", "fake-4", "fake-5"), settings.variants().map { it.label })
        assertEquals(60, order.size)
        assertTrue(order.groupingBy { it.label }.eachCount().values.all { it == 10 })
        assertNotEquals(settings.variants().flatMap { v -> List(10) { v } }, order, "попытки вперемешку, а не подряд одного варианта (§6.2)")
        val again = DesyncTrial(Recording(), engine, clock, core.log, java.util.Random(7)::nextInt).schedule(settings)
        assertEquals(order, again, "зерно теста — тот же порядок (D-21)")
    }

    @Test
    fun runRecordsOutcomesPausesAndWhetherTheTrickHappened() {
        val compiler = Recording()
        var applied = 0L
        // Мост делает приём на всех вариантах, кроме fake-4: там «имени не нашлось».
        val checker = HealthChecker { _, _ ->
            val p = compiler.last!!
            clock.advance(if (p.desync == null) 100 else 140)
            if (p.desync != null && p.desync != DesyncTrick.Fake(4)) applied++
            when {
                p.splitClientHello -> Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "сервер не ответил")
                p.desync == DesyncTrick.Fake(5) -> Outcome.failure(DiagCode.HEALTH_CHECK_FAILED, "TLS не сложился")
                else -> Outcome.Success(Unit)
            }
        }
        val trial = DesyncTrial(compiler, engine, clock, core.log, java.util.Random(1)::nextInt) { DesyncCounters(applied, 0) }
        val pauses = mutableListOf<Long>()
        val settings = TrialSettings(ttlFrom = 4, ttlTo = 5, attempts = 3, pauseMillis = 2_000)
        val ir = ir()
        val report = assertIs<Outcome.Success<TrialReport>>(
            runBlocking { trial.run(ir, ir.profiles.single().id, checker, settings, listOf("network" to "WIFI"), { pauses += it }) },
        ).value
        assertEquals(15, report.attempts.size)
        assertEquals(List(14) { 2_000L }, pauses, "пауза — между попытками, не перед первой (D-14)")
        assertTrue(compiler.plans.drop(1).all { !it.withTun }, "попытка — без TUN: туннель в замере не участвует")
        val byVariant = report.summaries.associateBy { it.variant }
        assertEquals(3, byVariant.getValue("plain").ok)
        assertEquals(100L, byVariant.getValue("plain").medianMillis)
        assertEquals(mapOf(DiagCode.ENDPOINT_UNREACHABLE to 3), byVariant.getValue("split").failures)
        assertEquals(0, byVariant.getValue("fake-5").ok)
        assertNull(byVariant.getValue("fake-5").medianMillis)
        assertEquals(3, byVariant.getValue("fake-4").notApplied, "приёма не было — так и записано, а не «прошло с приёмом»")
        assertEquals(0, byVariant.getValue("disorder").notApplied)
        assertTrue(report.attempts.filter { it.variant == "plain" || it.variant == "split" }.all { it.applied == null })
        val events = (core.logSink as LogHistory).snapshot()
        assertEquals(15, events.count { it.event == "desync_trial" })
        assertEquals(5, events.count { it.event == "desync_trial_summary" })
        assertTrue(events.single { it.event == "desync_trial_started" }.fields["network"] == "WIFI")
    }

    @Test
    fun serverWithoutTlsOverTcpIsRefusedBeforeTheFirstAttempt() {
        val compiler = Recording(noTls = true)
        var checks = 0
        val r = runBlocking {
            val ir = ir()
            val checker = HealthChecker { _, _ ->
                checks++
                Outcome.Success(Unit)
            }
            DesyncTrial(compiler, engine, clock, core.log, java.util.Random(1)::nextInt).run(ir, ir.profiles.single().id, checker, TrialSettings(), pause = {})
        }
        assertEquals(DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED, assertIs<Outcome.Failure>(r).errors.single().code)
        assertEquals(0, checks)
    }

    @Test
    fun badSettingsAreRefused() {
        assertEquals(null, TrialSettings().problem())
        for (bad in listOf(
            TrialSettings(ttlFrom = 0),
            TrialSettings(ttlTo = 65),
            TrialSettings(ttlFrom = 9, ttlTo = 3),
            TrialSettings(ttlFrom = 1, ttlTo = 40),
            TrialSettings(attempts = 0),
            TrialSettings(pauseMillis = 10),
        )) {
            assertTrue(bad.problem() != null, bad.toString())
            val r = runBlocking {
                val ir = ir()
                val ok = HealthChecker { _, _ -> Outcome.Success(Unit) }
                DesyncTrial(Recording(), engine, clock, core.log, java.util.Random(1)::nextInt).run(ir, ir.profiles.single().id, ok, bad, pause = {})
            }
            assertIs<Outcome.Failure>(r)
        }
    }
}
