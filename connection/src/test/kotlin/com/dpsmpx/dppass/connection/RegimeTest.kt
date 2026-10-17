package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.RestrictionClass
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Режим сети (D-64): память о белом списке, мягкий порядок плана, отдельный опыт, опровержение. */
class RegimeTest {
    private fun assess(c: NetworkCondition): NetworkAssessment = runBlocking {
        val clock = ManualClock(0)
        NetworkAssessor(SimulatedNetwork(c), ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE)
    }

    private val allowlist = assess(NetworkCondition.ALLOWLIST_LIKE)
    private val underList = NetworkContext.of(allowlist)
    private val multi: ConfigIr = ir("valid-multi.json")
    private fun profile(id: String) = multi.profiles.first { it.id.value == id }

    @Test
    fun memoryKeepsOnlyAFreshAllowlistOfTheSameNetwork() {
        assertEquals(RestrictionClass.ALLOWLIST_LIKE, allowlist.restriction)
        val clock = ManualClock(1_000)
        val m = RegimeMemory(clock, ttlMillis = 30_000)
        assertNull(m.allowlist(7), "проверки не было — режим неизвестен")
        m.remember(allowlist, network = 7)
        assertEquals(allowlist, m.allowlist(7))
        assertNull(m.allowlist(8), "другая сеть — другой режим")
        assertNull(m.allowlist(null), "сеть не узнать — режим неизвестен")
        clock.advance(29_999)
        assertEquals(allowlist, m.allowlist(7))
        clock.advance(1)
        assertNull(m.allowlist(7), "белые списки выключают: проверка устарела")
        assertEquals(30_000, m.ageMillis())

        // Новая проверка «не белый список» — тоже сведение: прежний список забыт.
        m.remember(allowlist, 7)
        m.remember(assess(NetworkCondition.NORMAL), 7)
        assertNull(m.allowlist(7))
        m.remember(allowlist, 7)
        m.forget()
        assertNull(m.allowlist(7), "опровергнут — режим неизвестен")
        assertNull(m.ageMillis())
    }

    private fun model(): StabilityModel = StabilityModel().apply {
        for (i in 1..3L) {
            observe(ProfileId("xhttp-cdn"), underList, StabilityObservation(true, 300, timestampMillis = i * 1_000), profile("xhttp-cdn"), allowlist)
            observe(ProfileId("reality-1"), underList, StabilityObservation(false, 8_000, timestampMillis = i * 1_000), profile("reality-1"), allowlist)
        }
    }

    @Test
    fun underAllowlistItsOwnExperienceGoesBeforeLastKnownGood() {
        val book = HealthBook().apply { recordSuccess(ProfileId("reality-1"), 0) }
        val stability = model()
        val normal = CandidatePlanner.plan(multi, MockBackend.FULL, null, book, ProfileId("reality-1"), 10_000, stability = stability)
        assertEquals("reality-1", normal.attempts.first().profile.id.value, "без режима — последний удачный, как прежде")

        val p = CandidatePlanner.plan(multi, MockBackend.FULL, null, book, ProfileId("reality-1"), 10_000, stability = stability, regime = allowlist)
        assertEquals("xhttp-cdn", p.attempts.first().profile.id.value, "под белым списком — тот, что под ним работал")
        assertTrue("под белым списком работал" in p.attempts.first().reasons, p.attempts.first().reasons.toString())
        // Мягко: никто не исключён из-за режима — неотмеченные серверы остаются в плане.
        assertTrue(p.excluded.none { "белый список" in it.reason }, p.excluded.toString())
        val all = p.attempts.map { it.profile.id } + p.excluded.map { it.profileId }
        assertEquals(multi.profiles.map { it.id }.toSet(), all.toSet())
        p.attempts.firstOrNull { it.profile.id.value == "reality-1" }?.let { assertTrue("под белым списком отказывал" in it.reasons, it.reasons.toString()) }
        assertTrue(p.attempts.any { "под белым списком ещё не пробовался" in it.reasons })

        // Выбор пользователя (D-34) — всё равно первым.
        val chosen = CandidatePlanner.plan(
            multi, MockBackend.FULL, null, book, ProfileId("reality-1"), 10_000, preferred = ProfileId("reality-1"), stability = stability, regime = allowlist,
        )
        assertEquals("reality-1", chosen.attempts.first().profile.id.value)

        // Оценка проверки (жёсткая, D-15) по-прежнему исключает неотмеченных — это другой путь.
        val hard = CandidatePlanner.plan(multi, MockBackend.FULL, allowlist, book, null, 10_000, stability = stability)
        assertEquals(listOf("domestic-relay"), hard.attempts.map { it.profile.id.value })
    }

    @Test
    fun experienceFromOtherNetworksDoesNotTransferUnderAllowlist() {
        val stability = StabilityModel()
        val unknown = NetworkContext.of(null)
        for (i in 1..12L) stability.observe(ProfileId("reality-1"), unknown, StabilityObservation(true, 80, timestampMillis = i * 1_000), profile("reality-1"))
        // В обычной сети опыт есть; под белым списком reality-1 — как сервер того же класса без опыта.
        assertTrue(stability.score(profile("reality-1"), null) > stability.score(profile("ss2022"), null))
        assertEquals(stability.score(profile("ss2022"), allowlist), stability.score(profile("reality-1"), allowlist))
        assertTrue(stability.failingIn(underList).isEmpty())
        assertEquals(setOf(ProfileId("reality-1")), model().failingIn(underList))
    }

    @Test
    fun attemptsUnderRegimeAreLearnedApartAndContradictionIsVisible() = runBlocking {
        val clock = ManualClock(1_000)
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), clock, "com.dpsmpx.dppass", PlatformTraits(true))
        val loaded = core.load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()).valueOrNull()!!
        val base = loaded.ir.profiles.single()
        val a = ProfileId("server-a")
        val b = ProfileId("server-b")
        val ir = loaded.ir.copy(profiles = listOf(a, b).map { base.copy(id = it, name = it.value) })
        assertIs<ActivationResult.Activated>(core.activation.activate(ir, PolicyService.OWN_DOCUMENT, "regime"))

        // Под белым списком a отказывает, b работает: опыт — в контексте списка, не в общем.
        var open = false
        val checker = HealthChecker { _, p -> if (p.id == a && !open) Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "сброс") else Outcome.Success(Unit) }
        val first = assertIs<ConnectionReport.Connected>(core.connect(null, checker, null, preferred = a, regime = allowlist) { clock.advance(it) })
        assertEquals(b, first.profileId)
        assertEquals(1, core.stability.stats(a, underList).observations)
        assertEquals(0, core.stability.stats(a, NetworkContext.of(null)).observations, "общий опыт не тронут")
        assertEquals(setOf(a), core.failingUnder(allowlist))
        first.session.stop()

        // Список выключили: a подключился — это опровержение, которое видит вызывающий.
        open = true
        clock.advance(10 * 60_000)
        val failing = core.failingUnder(allowlist)
        val second = assertIs<ConnectionReport.Connected>(core.connect(null, checker, null, preferred = a, regime = allowlist) { clock.advance(it) })
        assertEquals(a, second.profileId)
        assertTrue(second.profileId in failing)
    }
}
