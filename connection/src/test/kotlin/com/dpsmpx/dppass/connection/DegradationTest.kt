package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
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
import kotlin.test.assertTrue

/** Сбой выбранного сервера (D-58): отказ в журнале здоровья, вопрос, согласие заранее, «Остаться». */
class DegradationTest {
    private val clock = ManualClock(1_000)
    private val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), clock, "com.dpsmpx.dppass", PlatformTraits(true))
    private val a = ProfileId("server-a")
    private val b = ProfileId("server-b")
    private val c = ProfileId("server-c")
    private val probe = Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, "через сервер профиля за 8000 мс не пришло ни байта")

    private fun activate(ids: List<ProfileId>) = runBlocking {
        val loaded = core.load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()).valueOrNull()!!
        val base = loaded.ir.profiles.single()
        val ir = loaded.ir.copy(profiles = ids.map { base.copy(id = it, name = it.value) })
        assertIs<ActivationResult.Activated>(core.activation.activate(ir, PolicyService.OWN_DOCUMENT, "test-" + ids.size))
    }

    @Test
    fun degradationEndsLastKnownGoodSoAutomaticPlanStartsElsewhere() {
        activate(listOf(a, b, c))
        core.health.recordSuccess(a, clock.nowMillis())
        assertEquals(a, core.plan(null)!!.attempts.first().profile.id, "последний удачный — первым")

        val d = assertIs<Degradation.Reconnect>(core.degraded(a, probe, preferred = null, autoSwitch = false), "«Автоматически» — не спрашивают")
        assertEquals(probe, d.reason)
        val plan = core.plan(null)!!
        assertNotEquals(a, plan.attempts.first().profile.id)
        assertTrue(plan.attempts.none { it.profile.id == a }, "сбоивший сервер — на паузе после отказа")
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, core.health.of(a).lastFailure)
    }

    @Test
    fun userChoiceIsReplacedOnlyWithConsent() {
        activate(listOf(a, b, c))
        val ask = assertIs<Degradation.Ask>(core.degraded(a, probe, preferred = a, autoSwitch = false))
        assertEquals(a, ask.from.id)
        assertNotEquals(a, ask.to.id)
        assertEquals(probe, ask.reason)
        // Пока ответа нет, выбор пользователя — по-прежнему первым (D-34).
        assertEquals(a, core.plan(null, a)!!.attempts.first().profile.id)

        val switch = assertIs<Degradation.Switch>(core.degraded(a, probe, preferred = a, autoSwitch = true), "тумблер — согласие заранее")
        assertEquals(a, switch.from.id)
        assertNotEquals(a, switch.to.id)

        // «Остаться» — больше не спрашивают, и с тумблером тоже.
        assertIs<Degradation.Reconnect>(core.degraded(a, probe, preferred = a, autoSwitch = false, declined = setOf(a)))
        assertIs<Degradation.Reconnect>(core.degraded(a, probe, preferred = a, autoSwitch = true, declined = setOf(a)))
        // Сбоит не выбранный пользователем — замена по плану, без вопроса.
        assertIs<Degradation.Reconnect>(core.degraded(b, probe, preferred = a, autoSwitch = false))
    }

    @Test
    fun nothingToOfferMeansNoQuestion() {
        activate(listOf(a))
        assertIs<Degradation.Reconnect>(core.degraded(a, probe, preferred = a, autoSwitch = true), "сервер один")

        activate(listOf(a, b, c))
        core.health.recordFailure(b, DiagCode.ENDPOINT_UNREACHABLE, clock.nowMillis())
        core.health.recordFailure(c, DiagCode.ENDPOINT_UNREACHABLE, clock.nowMillis())
        assertIs<Degradation.Reconnect>(core.degraded(a, probe, preferred = a, autoSwitch = false), "остальные на паузе")

        // Устройство раздачи (D-55) в активной конфигурации не значится — замены ему нет.
        val relay = ProfileId("relay.0123456789ab")
        assertIs<Degradation.Reconnect>(core.degraded(relay, probe, preferred = relay, autoSwitch = true))
    }
}
