package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.DPpassCore
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
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Автообновление подписок на ПК (D-77): по сроку ядра, переподключение — только при смене подключённого сервера. */
class SubscriptionAutoUpdateTest {
    private val clock = ManualClock(1_000_000)
    private val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), clock, "com.dpsmpx.dppass", PlatformTraits(true))
    private val fetcher = Fetcher(LINKS)
    private var connected: ProfileId? = null
    private var reconnects = 0
    private var changes = 0
    private val auto = SubscriptionAutoUpdate(core, fetcher, "test", { connected }, { reconnects++ }) { changes++ }

    private class Fetcher(var body: String?) : SubscriptionFetcher {
        var requests = 0
        override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy): Outcome<FetchedPayload> {
            requests++
            val b = body ?: return Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "поставщик не ответил")
            return Outcome.Success(FetchedPayload(b.toByteArray(), emptyMap(), 0))
        }
    }

    @Test
    fun waitIsUntilDueButBetweenAMinuteAndAnHour() {
        assertEquals(60 * 60_000L, SubscriptionAutoUpdate.waitMillis(null), "автообновления нет — проверить через час")
        assertEquals(60_000L, SubscriptionAutoUpdate.waitMillis(0), "пора — не чаще раза в минуту")
        assertEquals(30 * 60_000L, SubscriptionAutoUpdate.waitMillis(30 * 60_000L))
        assertEquals(60 * 60_000L, SubscriptionAutoUpdate.waitMillis(5 * 60 * 60_000L))
    }

    @Test
    fun onlyAppliedSubscriptionByDueAndReconnectOnlyWhenConnectedServerChanged() = runBlocking {
        val id = core.subscriptions.add(URL, null).valueOrNull()!!.id
        assertNull(auto.runOnce(), "неприменённая подписка в фоне не обновляется")
        assertEquals(0, fetcher.requests)
        core.subscriptions.refresh(id, fetcher, "test")
        val manual = fetcher.requests
        assertNull(auto.runOnce(), "срок не вышел — без сети")
        assertEquals(manual, fetcher.requests)

        connected = core.activation.state.activeConfig!!.profiles.first().id
        clock.advance(HALF_DAY)
        // Поставщик добавил сервер, подключённый не изменился — соединения не рвутся.
        fetcher.body = LINKS + "vless://00000000-0000-4000-8000-000000000033@203.0.113.33:443?security=tls&sni=c.example.com#C\n"
        assertTrue(auto.runOnce()!!.applied)
        assertEquals(3, core.activation.state.activeConfig!!.profiles.size)
        assertEquals(0, reconnects)
        assertEquals(1, changes, "окно перерисовывает списки")

        clock.advance(HALF_DAY)
        // Подключённого сервера больше нет — переподключение.
        fetcher.body = "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"
        auto.runOnce()
        assertEquals(1, reconnects)

        // Туннеля нет — переподключать нечего.
        connected = null
        clock.advance(HALF_DAY)
        fetcher.body = LINKS
        assertTrue(auto.runOnce()!!.applied)
        assertEquals(1, reconnects)
    }

    @Test
    fun failedFetchIsLoggedAndDoesNotReconnect() = runBlocking {
        val id = core.subscriptions.add(URL, null).valueOrNull()!!.id
        core.subscriptions.refresh(id, fetcher, "test")
        connected = core.activation.state.activeConfig!!.profiles.first().id
        clock.advance(HALF_DAY)
        fetcher.body = null
        val run = auto.runOnce()!!
        assertFalse(run.applied)
        assertEquals(0, reconnects, "отказ поставщика не трогает туннель")
        assertEquals(2, core.activation.state.activeConfig!!.profiles.size, "прежние серверы остаются (D-08)")
        val events = (core.logSink as LogHistory).snapshot()
        assertTrue(events.any { it.event == "subscription_auto_update" && it.fields["applied"] == "false" })
        assertTrue(events.any { it.event == "diagnostic" && it.fields["code"] == DiagCode.SUBSCRIPTION_FETCH_FAILED.name }, "причина — в журнале окна")
        // Пауза после отказа — 30 минут: раньше в сеть не ходит.
        clock.advance(29 * 60_000L)
        assertNull(auto.runOnce())
        assertEquals(2, fetcher.requests)
    }

    @Test
    fun loopFirstChecksAfterAMinuteThenByDue() = runBlocking {
        val sleeps = mutableListOf<Long>()
        val job = auto.start(this) { d ->
            sleeps += d
            if (sleeps.size == 3) throw CancellationException("хватит")
        }
        job.join()
        // Подписок нет — срока нет: проверка раз в час.
        assertEquals(listOf(60_000L, 60 * 60_000L, 60 * 60_000L), sleeps)
        assertEquals(0, fetcher.requests)
    }

    private companion object {
        const val URL = "https://sub.example.com/api/sub/token-0123456789"
        const val HALF_DAY = 12 * 60 * 60_000L
        const val LINKS = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#A\n" +
            "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"
    }
}
