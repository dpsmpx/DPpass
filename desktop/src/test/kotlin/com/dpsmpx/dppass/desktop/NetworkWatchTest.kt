package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.Prober
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.runBlocking
import java.net.UnknownHostException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Смена сети ПК под туннелем (D-80): режим сессии заново, проверка новой сети после паузы, с пределом. */
class NetworkWatchTest {
    private val clock = ManualClock(1_000_000)
    private val sink = MemoryLogSink()
    private val log = Logger("test", sink, clock::nowMillis)
    private val home = LinuxNetwork("enp3s0", "0101A8C0", NetworkType.ETHERNET)
    private val phone = LinuxNetwork("wlan0", "012BA8C0", NetworkType.WIFI)
    private var now: LinuxNetwork? = home
    private var enabled = true
    private val retaken = mutableListOf<NetworkAssessment?>()
    private var checks = 0

    /** В «телефонной» сети — белый список, дома — без ограничений. */
    private val check = DesktopNetworkCheck(
        log,
        LinuxProbeNetwork({ 0 }, { throw UnknownHostException(it) }),
        network = { now },
        prober = {
            Prober { r ->
                val allowlist = now == phone
                val outcome = when {
                    r.kind == ProbeKind.CAPTIVE -> ProbeOutcome.INCONCLUSIVE
                    !allowlist || r.target == ProbeTarget.DOMESTIC || r.kind == ProbeKind.DNS -> ProbeOutcome.SUCCESS
                    r.kind == ProbeKind.UDP -> ProbeOutcome.TIMEOUT
                    else -> ProbeOutcome.REFUSED
                }
                ProbeResult(r, outcome, 10)
            }
        },
        clock = clock,
        pause = { clock.advance(it) },
    )

    private val watch = NetworkWatch(log, check, NetworkChangeChecks(clock), { enabled }, { retaken += it }, { now })
    private val sleep: suspend (Long) -> Unit = { clock.advance(it) }

    private fun events(name: String) = sink.snapshot().filter { it.event == name }

    @Test
    fun firstNetworkIsNotAChangeAndTheSameNetworkAgainNeither() {
        assertNull(watch.observe(), "сеть подключения — не смена")
        assertNull(watch.observe())
        now = null
        assertNull(watch.observe(), "сеть пропала — не смена")
        now = home
        assertNull(watch.observe(), "та же сеть снова — не смена")
        assertTrue(retaken.isEmpty())
        assertEquals(listOf("available", "lost", "available"), events("underlying_network").map { it.fields["state"] })
    }

    @Test
    fun changedNetworkIsCheckedAfterThePauseAndTheRegimeRetaken() = runBlocking {
        watch.observe()
        now = phone
        val key = assertNotNull(watch.observe())
        assertEquals(listOf<NetworkAssessment?>(null), retaken, "у новой сети режим неизвестен, пока её не проверили")
        val changed = events("network_changed").single()
        assertEquals("ETHERNET", changed.fields["from"])
        assertEquals("WIFI", changed.fields["to"])

        val before = clock.nowMillis()
        watch.afterChange(key, sleep)
        assertTrue(clock.nowMillis() - before >= NetworkChangeChecks.SETTLE_MILLIS, "сеть ещё устанавливается — проверка после паузы")
        assertEquals("NETWORK_CHANGE", events("network_check").single().fields["trigger"])
        assertEquals(RestrictionClass.ALLOWLIST_LIKE, retaken.last()?.restriction, "под белым списком новой сети опыт сессии — его")
        assertTrue(sink.snapshot().none { e -> e.fields.values.any { "wlan0" in it || "012BA8C0" in it } }, "сети в журнале нет")
    }

    @Test
    fun disabledCheckIsSkippedWithReason() = runBlocking {
        enabled = false
        watch.observe()
        now = phone
        watch.afterChange(assertNotNull(watch.observe()), sleep)
        assertEquals("disabled", events("network_check_skipped").single().fields["reason"])
        assertTrue(events("network_check").isEmpty())
    }

    @Test
    fun networkThatChangedAgainDuringThePauseIsNotChecked() = runBlocking {
        watch.observe()
        now = phone
        val first = assertNotNull(watch.observe())
        now = home
        assertNotNull(watch.observe())
        // Проверка первой смены: сеть уже другая — её проверит своя смена.
        watch.afterChange(first, sleep)
        assertTrue(events("network_check").isEmpty())
    }

    @Test
    fun atMostFourChecksPerHour() = runBlocking {
        watch.observe()
        repeat(5) {
            now = if (now == home) phone else home
            watch.afterChange(assertNotNull(watch.observe()), sleep)
            checks = events("network_check").size
        }
        assertEquals(NetworkChangeChecks.MAX_PER_HOUR, checks, "граница Wi-Fi — не залп к ориентирам (D-14)")
        assertEquals("limit", events("network_check_skipped").last().fields["reason"])
    }
}
