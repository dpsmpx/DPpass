package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.AppMode
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.subscriptions.FetchPolicy
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionRequest
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Без сервера на ПК (D-83): когда туннель без сервера, что Linux выражает и переход к серверу. */
class DesktopServerlessTest {
    private val core = DPpassCore(
        MockBackendCompiler(),
        MockProxyEngine(),
        InMemoryBlobStore(),
        ManualClock(1_000_000),
        DesktopGraph.SELF,
        PlatformTraits(true),
    )
    private val sites = SplitSites(domains = listOf("example.com"))

    @Test
    fun serverlessOnlyWithoutServersAndWithSomethingToSplit() {
        assertTrue(core.serverlessReady(sites, ServerlessSettings.DEFAULT, relaySelected = false), "серверов нет, список есть")
        assertFalse(
            core.serverlessReady(SplitSites.NONE, ServerlessSettings.DEFAULT, relaySelected = false),
            "списка нет, остальное напрямую — туннель не нужен",
        )
        assertTrue(core.serverlessReady(SplitSites.NONE, ServerlessSettings.DEFAULT.copy(rest = ServerlessSettings.Rest.SPLIT), relaySelected = false))
    }

    @Test
    fun linuxExpressesTheServerlessTunnelForAllPrograms() {
        val spec = assertNotNull(core.tunnelSpecFor(core.serverlessConfig(ServerlessSettings.DEFAULT)).valueOrNull())
        assertNull(LinuxRoutes.appPolicyProblem(spec, DesktopGraph.SELF), "все программы, кроме DPpass, — метка ядра")
        // Свой выбор приложений Linux не выразит — его на ПК и нет в меню.
        val own = ServerlessSettings.DEFAULT.copy(apps = ServerlessSettings.Apps.OWN, ownMode = AppMode.ONLY, ownApps = setOf("org.example.browser"))
        val ownSpec = assertNotNull(core.tunnelSpecFor(core.serverlessConfig(own)).valueOrNull())
        assertNotNull(LinuxRoutes.appPolicyProblem(ownSpec, DesktopGraph.SELF))
    }

    @Test
    fun firstServersReplaceTheServerlessTunnel() = runBlocking {
        val id = core.subscriptions.add("https://sub.example.com/api/sub/token-0123456789", null).valueOrNull()!!.id
        val run = assertNotNull(core.subscriptions.refresh(id, Fetcher, "test").valueOrNull())
        assertTrue(run.applied)
        assertTrue(run.needsReconnect(ServerlessPlan.PROFILE_ID), "туннель без сервера — переподключение уже через сервер")
        assertFalse(core.serverlessReady(sites, ServerlessSettings.DEFAULT, relaySelected = false), "есть серверы — только через них")
    }

    @Test
    fun serverlessChoiceSurvivesRestartAndAppsAreAlwaysTheSame() {
        val file = File(Files.createTempDirectory("dppass-prefs").toFile().also { it.deleteOnExit() }, "settings.properties")
        assertEquals(ServerlessSettings.DEFAULT, DesktopPrefs(file).serverless)
        DesktopPrefs(file).serverless = ServerlessSettings.DEFAULT.copy(rest = ServerlessSettings.Rest.SPLIT, dns = ServerlessSettings.Dns.SYSTEM)
        val again = DesktopPrefs(file).serverless
        assertEquals(ServerlessSettings.Rest.SPLIT, again.rest)
        assertEquals(ServerlessSettings.Dns.SYSTEM, again.dns)
        assertEquals(ServerlessSettings.DEFAULT.apps, again.apps, "выбора приложений на ПК нет")
    }

    private object Fetcher : SubscriptionFetcher {
        override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy): Outcome<FetchedPayload> = Outcome.Success(
            FetchedPayload("vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#A\n".toByteArray(), emptyMap(), 0),
        )
    }
}
