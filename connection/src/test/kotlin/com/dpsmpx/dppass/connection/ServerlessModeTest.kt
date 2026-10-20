package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Без сервера (D-73): когда режим доступен, что из выбора пользователя получает ядро и TUN, отказ пробы. */
class ServerlessModeTest {
    private val engine = MockProxyEngine()

    private fun core() = DPpassCore(MockBackendCompiler(), engine, InMemoryBlobStore(), ManualClock(1_000), "com.dpsmpx.dppass", PlatformTraits(true))

    private val sites = SplitSites.parse("example.com\ngeosite:example-a").valueOrNull()!!

    @Test
    fun onlyWithoutServersAndWithSomethingToDo() = runBlocking {
        val core = core()
        val split = ServerlessSettings(rest = ServerlessSettings.Rest.SPLIT)
        assertTrue(core.serverlessReady(sites, ServerlessSettings.DEFAULT, relaySelected = false))
        assertTrue(core.serverlessReady(SplitSites.NONE, split, relaySelected = false), "разбиение всего — дело и без списка")
        assertFalse(core.serverlessReady(SplitSites.NONE, ServerlessSettings.DEFAULT, relaySelected = false), "всё напрямую — туннель ни к чему")
        assertFalse(core.serverlessReady(sites, ServerlessSettings.DEFAULT, relaySelected = true), "устройство раздачи — это сервер")

        // Есть серверы — только через них: их отказ на режим без сервера не переключает (D-05).
        val source = File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()
        assertIs<ActivationResult.Activated>(core.importAndActivate(source).valueOrNull())
        assertFalse(core.serverlessReady(sites, split, relaySelected = false))
    }

    @Test
    fun configFollowsTheChoices() {
        val policy = UserPolicy(appMode = AppMode.EXCEPT, apps = setOf("com.example.bank"), dns = DnsProvider.QUAD9, bypassLan = false)
        val base = ServerlessMode.config(ServerlessSettings.DEFAULT, policy)
        assertTrue(base.profiles.isEmpty())
        assertEquals(RouteAction.DIRECT, base.routing.defaultAction)
        assertTrue(base.routing.rules.isEmpty())
        assertFalse(base.routing.bypassLan, "локальные сети — как в политике")
        assertEquals(AppPolicy.ExceptApps(setOf("com.example.bank")), base.routing.apps, "приложения — как с сервером")
        val server = base.dns.servers.single()
        assertEquals(DnsTransport.Https(DnsProvider.QUAD9.url), server.transport)
        assertEquals(DnsRoute.DIRECT, server.route, "через туннель DNS вести некуда")

        val own = ServerlessSettings(apps = ServerlessSettings.Apps.OWN, ownMode = AppMode.ONLY, ownApps = setOf("com.example.browser"))
        assertEquals(AppPolicy.OnlyApps(setOf("com.example.browser")), ServerlessMode.config(own, policy).routing.apps)
        assertEquals(AppPolicy.AllApps, ServerlessMode.config(ServerlessSettings(apps = ServerlessSettings.Apps.ALL), policy).routing.apps)
        val system = ServerlessMode.config(ServerlessSettings(dns = ServerlessSettings.Dns.SYSTEM), policy)
        assertEquals(DnsTransport.System, system.dns.servers.single().transport)

        val plan = ServerlessMode.plan(ServerlessSettings(rest = ServerlessSettings.Rest.SPLIT), sites, policy)
        assertTrue(plan.splitRest)
        assertEquals(sites, plan.splitSites)
    }

    @Test
    fun settingsFromThePhoneAreStrictButNeverBreak() {
        val s = ServerlessSettings.of("split", "system", "own", "except", setOf("com.example.a"))
        val want = ServerlessSettings(
            ServerlessSettings.Rest.SPLIT,
            ServerlessSettings.Dns.SYSTEM,
            ServerlessSettings.Apps.OWN,
            AppMode.EXCEPT,
            setOf("com.example.a"),
        )
        assertEquals(want, s)
        // Значение будущего выпуска или порча — выбор по умолчанию, а не падение.
        assertEquals(ServerlessSettings.DEFAULT, ServerlessSettings.of(null, "dot", "some", null, emptySet()))
        for (r in ServerlessSettings.Rest.entries) assertEquals(r, ServerlessSettings.of(r.wire, null, null, null, emptySet()).rest)
        for (d in ServerlessSettings.Dns.entries) assertEquals(d, ServerlessSettings.of(null, d.wire, null, null, emptySet()).dns)
        for (a in ServerlessSettings.Apps.entries) assertEquals(a, ServerlessSettings.of(null, null, a.wire, null, emptySet()).apps)
    }

    @Test
    fun connectsWithTheListAndStopsWhenDnsDoesNotAnswer() = runBlocking<Unit> {
        val core = core()
        val ok = core.connectServerless(null, sites, ServerlessSettings.DEFAULT) { _, _ -> Outcome.Success(Unit) }
        val session = assertIs<Outcome.Success<EngineSession>>(ok).value
        assertEquals(ServerlessPlan.PROFILE_ID, session.compiled.profileId)
        val payload = Json.parse(session.compiled.payloadForEngine()) as JsonObject
        assertEquals(Json.strings(listOf("example.com", "geosite:example-a")), payload["split_sites"])
        assertEquals(Json.bool(false), payload["split_rest"])
        session.stop()

        // DoH напрямую не ответил: ядро остановлено, причина — с подсказкой про системный DNS.
        val probe = Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, "напрямую за 8000 мс не пришло ни байта")
        var probed: ServerlessPlan? = null
        val failed = assertIs<Outcome.Failure>(
            core.connectServerless(null, sites, ServerlessSettings.DEFAULT) { s, dns ->
                assertEquals(EngineState.RUNNING, s.state())
                probed = ServerlessPlan(dns, sites, false)
                Outcome.failure(probe)
            },
        )
        assertEquals(DiagCode.ENDPOINT_UNREACHABLE, failed.errors.single().code)
        assertTrue("системный DNS" in failed.errors.single().message)
        assertEquals(listOf(probe), failed.errors.single().causes)
        assertEquals(DnsRoute.DIRECT, probed!!.dns.servers.single().route)
        // Ядро свободно: следующий запуск не упирается в «уже запущено».
        assertIs<Outcome.Success<EngineSession>>(core.connectServerless(null, sites, ServerlessSettings.DEFAULT) { _, _ -> Outcome.Success(Unit) })
    }
}
