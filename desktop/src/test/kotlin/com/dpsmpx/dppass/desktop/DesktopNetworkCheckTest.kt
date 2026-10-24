package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
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
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Проверка сети на ПК (D-79): пробы мимо туннеля, память режима по сети, тишина наблюдателя. */
class DesktopNetworkCheckTest {
    private val clock = ManualClock(1_000_000)
    private val sink = MemoryLogSink()
    private val log = Logger("test", sink, clock::nowMillis)
    private var network: LinuxNetwork? = LinuxNetwork("wlan0", "0101A8C0", NetworkType.WIFI)
    private var quietSeen = false

    private fun check(markOk: Boolean = true, answer: (ProbeKind, ProbeTarget) -> ProbeOutcome): DesktopNetworkCheck {
        lateinit var c: DesktopNetworkCheck
        val probes = LinuxProbeNetwork({ if (markOk) 0 else -1 }, { throw UnknownHostException(it) })
        c = DesktopNetworkCheck(
            log,
            probes,
            network = { network },
            prober = {
                Prober { request ->
                    quietSeen = quietSeen || c.probesQuiet()
                    ProbeResult(request, answer(request.kind, request.target), 10)
                }
            },
            clock = clock,
            pause = { clock.advance(it) },
        )
        return c
    }

    /** Отечественное доступно, оба зарубежных закрыты по TCP и TLS, имена резолвятся (как на телефоне 17.10.2026). */
    private val allowlist: (ProbeKind, ProbeTarget) -> ProbeOutcome = { kind, target ->
        when {
            kind == ProbeKind.CAPTIVE -> ProbeOutcome.INCONCLUSIVE
            target == ProbeTarget.DOMESTIC || kind == ProbeKind.DNS -> ProbeOutcome.SUCCESS
            kind == ProbeKind.UDP -> ProbeOutcome.TIMEOUT
            else -> ProbeOutcome.REFUSED
        }
    }

    @Test
    fun allowlistIsRememberedForThisNetworkOnly() = runBlocking {
        val c = check(answer = allowlist)
        val a = assertIs<Outcome.Success<*>>(c.run()).value
        assertEquals(RestrictionClass.ALLOWLIST_LIKE, (a as com.dpsmpx.dppass.network.NetworkAssessment).restriction)
        assertNotNull(c.regime(), "в той же сети — белый список")
        network = LinuxNetwork("wlan0", "0102A8C0", NetworkType.WIFI)
        assertNull(c.regime(), "другой шлюз — другая сеть: режим неизвестен")
        assertTrue(quietSeen, "пока идёт проверка, наблюдатель молчит")
        assertTrue(!c.busy())
        val events = sink.snapshot().map { it.event }
        assertTrue("network_check" in events && "network_assessed" in events && "network_probe" in events, events.toString())
        assertTrue(sink.snapshot().none { e -> e.fields.values.any { "0101A8C0" in it || "wlan0" in it } }, "сети в журнале нет")
    }

    @Test
    fun normalNetworkIsNotAnAllowlist() = runBlocking {
        val c = check { kind, _ -> if (kind == ProbeKind.CAPTIVE) ProbeOutcome.INCONCLUSIVE else ProbeOutcome.SUCCESS }
        assertIs<Outcome.Success<*>>(c.run())
        assertNull(c.regime(), "в план идёт только белый список")
    }

    @Test
    fun withoutMarkTheCheckIsRefusedAndNothingIsProbed() = runBlocking {
        var probed = 0
        val c = check(markOk = false) { _, _ ->
            probed++
            ProbeOutcome.SUCCESS
        }
        val r = assertIs<Outcome.Failure>(c.run())
        assertEquals(DiagCode.NETWORK_CHECK_UNAVAILABLE, r.errors.first().code)
        assertEquals(0, probed, "через туннель проба мерила бы сервер, а не сеть")
        assertNull(c.regime())
    }

    @Test
    fun withoutDefaultRouteTheNetworkIsOffline() = runBlocking {
        network = null
        val c = check { _, _ -> ProbeOutcome.SUCCESS }
        val a = assertIs<Outcome.Success<*>>(c.run()).value as com.dpsmpx.dppass.network.NetworkAssessment
        assertEquals(NetworkType.NONE, a.type)
    }
}
