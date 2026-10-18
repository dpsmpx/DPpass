package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ProbeBudgetTest {
    @Test
    fun noBurstsToTheSameTarget() {
        val clock = ManualClock(0)
        val b = ProbeBudget(clock, minIntervalMillis = 1000, maxPerWindow = 3, windowMillis = 10_000)
        assertTrue(b.tryAcquire(ProbeTarget.FOREIGN))
        assertFalse(b.tryAcquire(ProbeTarget.FOREIGN), "вторая проба без паузы — залп")
        assertEquals(1000, b.waitMillis(ProbeTarget.FOREIGN))
        assertTrue(b.tryAcquire(ProbeTarget.DOMESTIC), "другой ориентир — можно")
        clock.advance(1000)
        assertTrue(b.tryAcquire(ProbeTarget.FOREIGN))
        clock.advance(1000)
        assertFalse(b.tryAcquire(ProbeTarget.FOREIGN), "окно исчерпано")
        clock.advance(10_000)
        assertTrue(b.tryAcquire(ProbeTarget.FOREIGN))
    }
}

class NetworkClassifierTest {
    private fun assess(c: NetworkCondition, type: NetworkType = NetworkType.MOBILE): Pair<NetworkAssessment, Int> = runBlocking {
        val clock = ManualClock(0)
        val net = SimulatedNetwork(c)
        val gaps = mutableListOf<Long>()
        val x = NetworkAssessor(net, ProbeBudget(clock)) { gaps += it; clock.advance(it) }.assess(type)
        x to net.probeCount
    }

    @Test
    fun table() {
        val expected = mapOf(
            NetworkCondition.NORMAL to RestrictionClass.NORMAL,
            NetworkCondition.DNS_BLOCKED to RestrictionClass.DEGRADED,
            NetworkCondition.DNS_DEGRADED to RestrictionClass.DEGRADED,
            NetworkCondition.IP_BLOCKED to RestrictionClass.NORMAL,
            NetworkCondition.TCP_REACHABLE_UDP_BLOCKED to RestrictionClass.NORMAL,
            NetworkCondition.TLS_DEGRADED to RestrictionClass.DEGRADED,
            NetworkCondition.HIGH_LATENCY to RestrictionClass.DEGRADED,
            NetworkCondition.PACKET_LOSS to RestrictionClass.DEGRADED,
            NetworkCondition.CAPTIVE_PORTAL to RestrictionClass.CAPTIVE,
            NetworkCondition.ALLOWLIST_LIKE to RestrictionClass.ALLOWLIST_LIKE,
            NetworkCondition.FULL_ENDPOINT_BLOCK to RestrictionClass.NORMAL,
            NetworkCondition.PROVIDER_BLOCKED to RestrictionClass.DEGRADED,
            NetworkCondition.OFFLINE to RestrictionClass.OFFLINE,
        )
        for ((c, cls) in expected) {
            val (x, _) = assess(c)
            assertEquals(cls, x.restriction, "$c: ${x.evidence}")
            assertTrue(x.evidence.isNotEmpty(), "$c: вывод без доказательств")
        }
    }

    @Test
    fun udpBlockIsVisibleButNotARestriction() {
        val (x, _) = assess(NetworkCondition.TCP_REACHABLE_UDP_BLOCKED)
        assertEquals(Reachability.BLOCKED, x.udp)
        assertEquals(Reachability.OK, x.tls)
    }

    @Test
    fun captivePortalStopsFurtherProbing() {
        val (_, probes) = assess(NetworkCondition.CAPTIVE_PORTAL)
        assertEquals(1, probes)
    }

    @Test
    fun noNetworkMeansNoProbes() {
        val (x, probes) = assess(NetworkCondition.NORMAL, NetworkType.NONE)
        assertEquals(RestrictionClass.OFFLINE, x.restriction)
        assertEquals(0, probes)
    }

    @Test
    fun tooFewObservationsIsUnknown() {
        val x = NetworkClassifier.classify(
            NetworkType.WIFI,
            listOf(ProbeResult(ProbeRequest(ProbeKind.TCP, ProbeTarget.DOMESTIC), ProbeOutcome.SUCCESS)),
        )
        assertEquals(RestrictionClass.UNKNOWN, x.restriction)
        assertEquals(Confidence.LOW, x.confidence)
    }
}

/** Бюджет и пропуски (D-60, телефон, 17.10.2026): пропуск — не вывод, повтор — после паузы. */
class ProbeSkipTest {
    @Test
    fun skippedForeignProbesAreNotNormal() {
        val probes = ProbePlan.STANDARD.map { r ->
            ProbeResult(r, if (r.target != ProbeTarget.DOMESTIC && r.kind != ProbeKind.DNS) ProbeOutcome.SKIPPED else ProbeOutcome.SUCCESS, 5)
        }
        val x = NetworkClassifier.classify(NetworkType.MOBILE, probes)
        assertEquals(RestrictionClass.UNKNOWN, x.restriction, x.evidence.toString())
        val udpOnly = ProbePlan.STANDARD.map { r -> ProbeResult(r, if (r.kind == ProbeKind.UDP) ProbeOutcome.SKIPPED else ProbeOutcome.SUCCESS, 5) }
        val y = NetworkClassifier.classify(NetworkType.WIFI, udpOnly)
        assertEquals(RestrictionClass.NORMAL, y.restriction)
        assertEquals(Confidence.MEDIUM, y.confidence)
        assertTrue(y.evidence.none { it == "все пробы прошли" }, y.evidence.toString())
    }

    @Test
    fun budgetSaysWhenAFullCheckFits() {
        val clock = ManualClock(0)
        val b = ProbeBudget(clock, minIntervalMillis = 0, maxPerWindow = 12, windowMillis = 60_000)
        assertEquals(0, b.waitForMillis(8))
        repeat(8) { clock.advance(1_000); assertTrue(b.tryAcquire(ProbeTarget.FOREIGN)) }
        // Занято 8 из 12: ещё 8 влезут, когда истечёт 4-я проба (t = 4 с + 60 с).
        assertEquals(64_000 - clock.nowMillis(), b.waitForMillis(8))
        assertEquals(0, b.waitForMillis(4))
        assertEquals(Long.MAX_VALUE, b.waitForMillis(13))
        clock.advance(60_000)
        assertEquals(0, b.waitForMillis(8))
    }
}

/** Пауза между замерами по кнопке (D-61): отсчёт и повтор. */
class CooldownTest {
    @Test
    fun countsDownAndRestarts() {
        val clock = ManualClock(1_000)
        val c = Cooldown(clock)
        assertEquals(0, c.remainingMillis(), "до первого замера ждать нечего")
        c.restart(60_000)
        assertEquals(60_000, c.remainingMillis())
        clock.advance(59_500)
        assertEquals(500, c.remainingMillis())
        clock.advance(1_000)
        assertEquals(0, c.remainingMillis(), "пауза прошла — не уходит в минус")
        c.restart(15_000)
        assertEquals(15_000, c.remainingMillis(), "новый замер — новая пауза, своя длина")
    }
}

/** Окно тишины наблюдателя (D-44, D-61): пока идёт свой замер и после него проба сессии не в счёт. */
class QuietWindowTest {
    @Test
    fun coversRunningMeasurementsAndTheGraceAfter() {
        val clock = ManualClock(1_000)
        val q = QuietWindow(clock, 15_000)
        assertFalse(q.active(), "до первого замера пробе ничто не мешает")
        q.begin()
        q.begin()
        q.end()
        clock.advance(60_000)
        assertTrue(q.active(), "один из двух замеров ещё идёт — сколько бы ни прошло")
        q.end()
        clock.advance(14_999)
        assertTrue(q.active(), "после замера — ещё окно")
        clock.advance(1)
        assertFalse(q.active(), "окно прошло")
        assertFailsWith<IllegalStateException> { q.end() }
    }

    /**
     * Ход 17 октября 2026 (0.7.2-dev, 14:30): замер скорости кончился в
     * 14:30:17.2, следом в 14:30:21.6 началась проверка сети, проба
     * наблюдателя шла 14:30:19.6–14:30:27.6 и провалилась по сроку 8 с.
     * Теперь она не начинается; а начатая до замера — не учитывается.
     */
    @Test
    fun probeOnTheDeviceTimelineIsNotCounted() {
        val clock = ManualClock(0)
        val q = QuietWindow(clock, 15_000)
        q.begin() // замер скорости, ~10 с
        clock.advance(10_000)
        q.end()
        clock.advance(2_400)
        assertTrue(q.active(), "проба через 2,4 с после замера не начинается")
        clock.advance(2_000)
        q.begin() // проверка сети, ~13 с
        clock.advance(13_000)
        q.end()
        clock.advance(15_000)
        assertFalse(q.active(), "через окно после проверки пробы снова идут")

        // Проба началась в тишине, а замер пришёл, пока она шла: исход — не про сервер.
        q.begin()
        clock.advance(8_000)
        assertTrue(q.active())
    }
}

/** Два зарубежных ориентира (D-62): закрыт поставщик — L4; закрыты оба — белый список. */
class SecondLandmarkTest {
    private fun probes(vararg pairs: Pair<ProbeRequest, ProbeOutcome>): List<ProbeResult> {
        val given = pairs.toMap()
        return ProbePlan.STANDARD.map { ProbeResult(it, given[it] ?: ProbeOutcome.SUCCESS, 40) }
    }

    private fun r(kind: ProbeKind, target: ProbeTarget) = ProbeRequest(kind, target)

    @Test
    fun oneProviderClosedIsL4NotForeignBlocked() {
        val x = NetworkClassifier.classify(
            NetworkType.MOBILE,
            probes(
                r(ProbeKind.TCP, ProbeTarget.FOREIGN) to ProbeOutcome.REFUSED,
                r(ProbeKind.TLS, ProbeTarget.FOREIGN) to ProbeOutcome.REFUSED,
                r(ProbeKind.UDP, ProbeTarget.FOREIGN) to ProbeOutcome.TIMEOUT,
                r(ProbeKind.BULK, ProbeTarget.FOREIGN) to ProbeOutcome.REFUSED,
            ),
        )
        assertEquals(RestrictionClass.DEGRADED, x.restriction, x.evidence.toString())
        assertEquals(Reachability.OK, x.tcp, "наружу TCP проходит — ко второму ориентиру")
        assertEquals(Reachability.OK, x.udp, "QUIC ко второму ориентиру прошёл")
        assertTrue(x.evidence.any { "L4" in it }, x.evidence.toString())
        assertTrue(x.evidence.none { it == "зарубежный адрес не отвечает по TCP" }, x.evidence.toString())
    }

    @Test
    fun bothForeignClosedWhileNamesResolveIsAllowlistLike() {
        val closed = listOf(ProbeTarget.FOREIGN, ProbeTarget.FOREIGN_ALT).flatMap { t ->
            listOf(r(ProbeKind.TCP, t) to ProbeOutcome.REFUSED, r(ProbeKind.TLS, t) to ProbeOutcome.REFUSED, r(ProbeKind.UDP, t) to ProbeOutcome.TIMEOUT)
        } + (r(ProbeKind.BULK, ProbeTarget.FOREIGN) to ProbeOutcome.REFUSED)
        val x = NetworkClassifier.classify(NetworkType.MOBILE, probes(*closed.toTypedArray()))
        assertEquals(RestrictionClass.ALLOWLIST_LIKE, x.restriction, x.evidence.toString())
        assertEquals(Confidence.MEDIUM, x.confidence, "имена резолвятся — не выше средней")
        assertEquals(Reachability.OK, x.dns)
    }

    @Test
    fun withOneLandmarkResolvingNamesStayDegraded() {
        // Наблюдение старого плана (одного ориентира) — без второго ориентира белый список не выводится.
        val old = ProbePlan.STANDARD.filter { it.target != ProbeTarget.FOREIGN_ALT }.map {
            val o = when {
                it.target == ProbeTarget.FOREIGN && it.kind == ProbeKind.UDP -> ProbeOutcome.TIMEOUT
                it.target == ProbeTarget.FOREIGN && it.kind != ProbeKind.DNS -> ProbeOutcome.REFUSED
                else -> ProbeOutcome.SUCCESS
            }
            ProbeResult(it, o, 40)
        }
        assertEquals(RestrictionClass.DEGRADED, NetworkClassifier.classify(NetworkType.MOBILE, old).restriction)
    }
}

/** Проверка сети при её смене (D-67): что считать сменой, пауза и предел за час. */
class NetworkChangeChecksTest {
    @Test
    fun firstAndRepeatedNetworkAreNotAChange() {
        val clock = ManualClock(1_000)
        val c = NetworkChangeChecks(clock, settleMillis = 20_000)
        assertFalse(c.onNetwork(7), "первая сеть сессии — её режим взят при подключении")
        assertFalse(c.onNetwork(7), "система повторила ту же сеть")
        assertNull(c.waitMillis(7), "смены не было — проверять нечего")
        assertFalse(c.tryStart(7))
    }

    @Test
    fun checkWaitsForTheNetworkToSettleAndRestartsOnAnotherChange() {
        val clock = ManualClock(1_000)
        val c = NetworkChangeChecks(clock, settleMillis = 20_000)
        c.onNetwork(7)
        assertTrue(c.onNetwork(8), "Wi-Fi → мобильная")
        assertEquals(20_000, c.waitMillis(8))
        assertNull(c.waitMillis(7), "прежнюю сеть не проверяют")
        clock.advance(15_000)
        assertFalse(c.tryStart(8), "сеть ещё устанавливается")
        assertTrue(c.onNetwork(9), "снова смена — отсчёт заново")
        assertNull(c.waitMillis(8))
        clock.advance(19_999)
        assertEquals(1, c.waitMillis(9))
        clock.advance(1)
        assertTrue(c.tryStart(9))
        assertNull(c.waitMillis(9), "проверка засчитана: без новой смены — не повторять")
        assertFalse(c.tryStart(9))
        assertTrue(c.onNetwork(7), "вернулись в прежнюю сеть — тоже смена")
    }

    @Test
    fun notMoreThanTheLimitPerHourWhenTheNetworkFlaps() {
        val clock = ManualClock(1_000)
        val c = NetworkChangeChecks(clock, settleMillis = 0, maxPerHour = 4)
        c.onNetwork(1)
        var checks = 0
        for (i in 0 until 40) {
            // На границе Wi-Fi: смена каждые 3 минуты, два часа подряд.
            c.onNetwork(if (i % 2 == 0) 2L else 1L)
            if (c.tryStart(if (i % 2 == 0) 2L else 1L)) checks++
            clock.advance(3 * 60_000)
        }
        assertEquals(8, checks, "40 смен за два часа — по 4 проверки в час, а не 40")
        clock.advance(60 * 60_000)
        c.onNetwork(3)
        assertTrue(c.tryStart(3), "час прошёл — снова можно")
    }
}
