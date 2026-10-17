package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.Reachability
import com.dpsmpx.dppass.network.RestrictionClass
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

private val MOBILE_NORMAL = NetworkContext(NetworkType.MOBILE, RestrictionClass.NORMAL)

private fun good(rtt: Long, t: Long) = StabilityObservation(success = true, rttMillis = rtt, timestampMillis = t)
private fun fail(t: Long, stalled: Boolean = false) = StabilityObservation(success = false, rttMillis = 5_000, stalled = stalled, timestampMillis = t)

private fun stats(vararg samples: StabilityObservation): StabilityStats =
    samples.fold(StabilityStats()) { s, o -> s.fold(o) }

class StabilityModelTest {
    @Test
    fun lowerBoundIsPessimisticAboutThinEvidence() {
        val few = stats(good(100, 1), good(110, 2), good(120, 3)) // 3 из 3
        val many = (1..100L).fold(StabilityStats()) { s, i -> s.fold(good(100, i)) } // 100 из 100
        assertTrue(few.reliabilityMean > 0.7)
        assertTrue(many.reliabilityLcb > few.reliabilityLcb, "95/100 должно обгонять 3/3 по нижней границе")
    }

    @Test
    fun jitterGrowsWithVaryingRttAndStaysLowWhenSteady() {
        val steady = (1..6L).fold(StabilityStats()) { s, i -> s.fold(good(100, i)) }
        val jumpy = stats(good(100, 1), good(300, 2), good(100, 3), good(320, 4), good(90, 5), good(310, 6))
        assertTrue(jumpy.jitterMillis > steady.jitterMillis, "скачущий RTT — больше джиттер")
    }

    @Test
    fun regimeShiftIsDetectedWhenFailuresSuddenlyCluster() {
        var s = (1..20L).fold(StabilityStats()) { a, i -> a.fold(good(100, i)) }
        assertFalse(s.regimeShift)
        for (i in 21..26L) s = s.fold(fail(i))
        assertTrue(s.regimeShift, "резкий рост отказов — смена режима (Пейдж — Хинкли)")
    }

    @Test
    fun singleFailureAfterGoodHistoryDoesNotTriggerRecovery() {
        val model = StabilityModel()
        val id = ProfileId("reality-1")
        for (i in 1..10L) model.observe(id, MOBILE_NORMAL, good(90, i))
        model.observe(id, MOBILE_NORMAL, fail(11))
        assertFalse(model.shouldRecover(id, MOBILE_NORMAL), "один сбой — не смена сервера (T14)")
    }

    @Test
    fun confirmedDegradationTriggersRecovery() {
        val model = StabilityModel()
        val id = ProfileId("reality-1")
        for (i in 1..6L) model.observe(id, MOBILE_NORMAL, good(90, i))
        for (i in 7..12L) model.observe(id, MOBILE_NORMAL, fail(i, stalled = true))
        assertTrue(model.shouldRecover(id, MOBILE_NORMAL), "подтверждённая деградация — переключение")
    }

    @Test
    fun oldExperienceDecaysTowardsPrior() {
        var s = (1..50L).fold(StabilityStats()) { a, i -> a.fold(fail(i)) }
        val before = s.reliabilityMean
        s = s.decayTo(StabilityStats.HALF_LIFE_MILLIS * 8) // восемь полураспадов
        assertTrue(s.reliabilityMean > before + 0.3, "за восемь полураспадов опыт почти забыт")
    }
}

class TransportAdvisorTest {
    private val profiles = ir("valid-multi.json").profiles
    private fun byClass(c: TransportClass): ServerProfile = profiles.first { it.transportClass == c }

    private val udpBlocked = NetworkAssessment(
        type = NetworkType.MOBILE, dns = Reachability.OK, tcp = Reachability.OK, tls = Reachability.OK,
        udp = Reachability.BLOCKED, bulk = Reachability.OK, captivePortal = false,
        restriction = RestrictionClass.DEGRADED, confidence = com.dpsmpx.dppass.network.Confidence.HIGH, evidence = emptyList(),
    )

    @Test
    fun experienceTransfersToUnseenServerOfSameClass() {
        val advisor = TransportAdvisor()
        val udp = byClass(TransportClass.UDP_QUIC)
        val tcp = byClass(TransportClass.TCP_STREAM)
        // UDP многократно не работает в udp-blocked сети.
        repeat(40) { advisor.learn(udp, udpBlocked, success = false) }
        repeat(40) { advisor.learn(tcp, udpBlocked, success = true) }
        assertTrue(advisor.predict(udp, udpBlocked) < advisor.predict(tcp, udpBlocked), "опыт класса переносится на сервер того же класса")
        assertTrue(advisor.weights().all { kotlin.math.abs(it) <= TransportAdvisor.CLAMP })
    }

    @Test
    fun trainingIsDeterministic() {
        fun train(): DoubleArray {
            val a = TransportAdvisor()
            repeat(20) { a.learn(byClass(TransportClass.UDP_QUIC), udpBlocked, false) }
            return a.weights()
        }
        assertTrue(train().contentEquals(train()))
    }
}

class SessionSupervisorTest {
    private val id = ProfileId("reality-1")

    @Test
    fun holdsThroughRareFailuresSwitchesOnConfirmedDegradation() {
        val sup = SessionSupervisor(StabilityModel(), id, MOBILE_NORMAL, minHoldMillis = 0)
        assertEquals(SessionSupervisor.Decision.HOLD, sup.onObservation(good(90, 1_000)))
        assertEquals(SessionSupervisor.Decision.HOLD, sup.onObservation(fail(2_000)))
        // Пошла череда отказов — переключение после подтверждения.
        var reconnected = false
        for (t in 3..8) {
            if (sup.onObservation(fail(t * 1_000L, stalled = true)) == SessionSupervisor.Decision.RECONNECT) reconnected = true
        }
        assertTrue(reconnected, "подтверждённая деградация ведёт к переподключению")
    }

    @Test
    fun switchesAreRateLimitedPerHour() {
        val model = StabilityModel()
        val sup = SessionSupervisor(model, id, MOBILE_NORMAL, maxSwitchesPerHour = 2, minHoldMillis = 0)
        var count = 0
        for (t in 1..200) {
            // Постоянные отказы: без предела было бы переподключение каждый тик.
            if (sup.onObservation(fail(t * 1_000L, stalled = true)) == SessionSupervisor.Decision.RECONNECT) count++
        }
        assertTrue(count <= 2, "не чаще предела переключений в час, было $count")
    }
}

class StabilityBookTest {
    @Test
    fun savesAndRestoresAggregatesWithoutLoss() {
        val store = InMemoryBlobStore()
        val book = StabilityBook(store)
        val model = StabilityModel()
        val id = ProfileId("edge-1")
        for (i in 1..5L) model.observe(id, MOBILE_NORMAL, good(120, i * 1_000))
        model.observe(id, MOBILE_NORMAL, fail(6_000))
        val before = model.stats(id, MOBILE_NORMAL)
        assertTrue(book.save(model) is Outcome.Success)

        val restored = book.load().valueOrNull()!!
        assertEquals(before, restored.stats(id, MOBILE_NORMAL))
    }

    @Test
    fun corruptStateGoesToQuarantineAndModelStartsEmpty() {
        val store = InMemoryBlobStore()
        val clock = ManualClock(0)
        val quarantine = Quarantine(store, clock)
        store.write(StabilityBook.KEY, "не модель DPpass".toByteArray())
        val book = StabilityBook(store, quarantine)
        val model = book.load().valueOrNull()!!
        assertEquals(0, model.size())
        assertEquals(1, quarantine.list().valueOrNull()!!.size, "повреждённое — в карантин, не затёрто")
    }

    @Test
    fun savedModelHasNoSecretsOrDeviceIdentifiers() {
        val store = InMemoryBlobStore()
        val book = StabilityBook(store)
        val model = StabilityModel()
        model.observe(ProfileId("reality-1"), MOBILE_NORMAL, good(100, 1_000))
        book.save(model)
        val text = String(store.read(StabilityBook.KEY).valueOrNull()!!)
        // Только числа и грубый контекст: ни адресов подписки, ни URL, ни учётных данных.
        assertTrue(text.startsWith("dppass-adaptive-v1"))
        assertFalse(text.contains("@"), "нет учётных данных ссылок")
        assertFalse(text.contains("http"), "нет URL")
        assertFalse(text.contains("://"), "нет адресов")
    }
}
