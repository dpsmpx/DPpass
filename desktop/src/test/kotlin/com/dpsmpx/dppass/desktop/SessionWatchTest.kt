package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.LogHistory
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.subscriptions.FetchPolicy
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionRequest
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Наблюдатель сеанса на ПК (D-78): череда сбоев — решение ядра (D-44, D-58), одиночные — нет (T14). */
class SessionWatchTest {
    private val clock = ManualClock(1_000_000)
    private val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), clock, "com.dpsmpx.dppass", PlatformTraits(true))
    private var preferred: ProfileId? = null
    private var autoSwitch = false
    private val declined = mutableSetOf<ProfileId>()
    private var monotonic = 0L

    private val first: ProfileId by lazy {
        runBlocking {
            val id = core.subscriptions.add("https://sub.example.com/api/sub/token-0123456789", null).valueOrNull()!!.id
            core.subscriptions.refresh(id, Fetcher, "test")
        }
        core.activation.state.activeConfig!!.profiles.first().id
    }

    private object Fetcher : SubscriptionFetcher {
        override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy) = Outcome.Success(
            FetchedPayload(
                (
                    "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#A\n" +
                        "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"
                    ).toByteArray(),
                emptyMap(),
                0,
            ),
        )
    }

    private fun watch(fails: (Int) -> Boolean): Pair<SessionWatch, () -> Int> {
        var n = 0
        val w = SessionWatch(
            core,
            first,
            core.activation.state.activeConfig!!.profiles.first(),
            {
                val i = n++
                // Проба шла 200 мс; отказ — как у Android: «ни байта» за срок.
                monotonic += 200
                if (fails(i)) Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "через сервер профиля за 8000 мс не пришло ни байта") else Outcome.Success(Unit)
            },
            { preferred },
            { autoSwitch },
            { declined.toSet() },
            { monotonic },
        )
        return w to { n }
    }

    /** Пробы раз в 15 с, пока не будет решения или не кончится [limit]. */
    private fun until(w: SessionWatch, limit: Int): Degradation? {
        repeat(limit) {
            clock.advance(SessionWatch.INTERVAL_MILLIS)
            w.step()?.let { return it }
        }
        return null
    }

    @Test
    fun isolatedFailuresLikeTheAuthorsLogDoNotReconnect() {
        // Журнал автора 24.10.2026: каждая двенадцатая проба не уложилась в срок, подряд — ни разу.
        val (w, _) = watch { it % 12 == 11 }
        assertNull(until(w, 120))
    }

    @Test
    fun healthyServerIsKept() {
        val (w, _) = watch { false }
        assertNull(until(w, 60))
    }

    @Test
    fun failingAutomaticServerReconnectsByPlan() {
        val (w, probes) = watch { true }
        val d = until(w, 20)
        assertIs<Degradation.Reconnect>(d, "выбран «Автоматически» — просто план заново")
        assertTrue(probes() >= 2, "один сбой — не деградация (T14)")
        val events = (core.logSink as LogHistory).snapshot()
        assertTrue(
            events.any {
                it.event == "adaptive_probe_failed" && it.fields["code"] == DiagCode.ENDPOINT_UNREACHABLE.name && "ни байта" in it.fields["reason"].orEmpty()
            },
        )
        assertTrue(events.any { it.event == "adaptive_reconnect" })
    }

    @Test
    fun failingChosenServerAsksOrSwitchesWithConsent() {
        preferred = first
        val ask = assertIs<Degradation.Ask>(until(watch { true }.first, 20))
        assertEquals(first, ask.from.id)
        assertNotEquals(first, ask.to.id)

        autoSwitch = true
        val switch = assertIs<Degradation.Switch>(until(watch { true }.first, 20))
        assertEquals(first, switch.from.id)
    }

    @Test
    fun answeredStayIsNotAskedAgain() {
        preferred = first
        declined += first
        assertIs<Degradation.Reconnect>(assertNotNull(until(watch { true }.first, 20)))
    }
}
