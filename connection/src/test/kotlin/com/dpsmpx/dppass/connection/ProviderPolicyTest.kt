package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.Conditions
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsRule
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.Layers
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.Rule
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.subscriptions.FetchPolicy
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.RoutingBinding
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionRequest
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Маршрутизация и DNS поставщика из подписки-документа — с согласием, свои настройки поверх (D-98). Данные синтетические. */
class ProviderPolicyTest {
    private val clock = ManualClock(1_000_000)
    private val blobs = InMemoryBlobStore()

    private fun core() = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))

    private class Fetcher(private val clock: ManualClock, var body: String) : SubscriptionFetcher {
        override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy) =
            Outcome.Success(FetchedPayload(body.toByteArray(), emptyMap(), clock.nowMillis()))
    }

    private val doh = DnsTransport.Https("https://dns.example.net/dns-query")
    private val provider = RoutingPolicy(
        rules = listOf(Rule(RuleId("p-ads"), Conditions(domains = listOf(DomainMatcher.Suffix("ads.example.com"))), RouteAction.BLOCK)),
        defaultAction = RouteAction.DIRECT,
        apps = AppPolicy.OnlyApps(setOf("org.example.browser")),
        bypassLan = false,
        automaticDomestic = true,
    )
    private val providerDns = DnsPolicy(
        servers = listOf(DnsServer("p-doh", doh, DnsRoute.TUNNEL)),
        defaultServerId = "p-doh",
        rules = listOf(DnsRule(listOf(DomainMatcher.Suffix("example.ru")), emptyList(), "p-doh")),
    )

    @Test
    fun ownLayerGoesOverProviderAndComesOffExactly() {
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true, lists = SiteLists(proxy = list("example.org"), direct = list("example.net")))
        val lists = SiteLists(block = list("tracker.example.com"))
        val r = ProviderPolicy.routing(provider, p, lists)
        // Свои списки, затем списки поставщика из профиля (D-94), затем правила документа; режима и рекламы политики нет.
        assertEquals(listOf("own-proxy-sites", "own-direct-sites", "provider-block-sites", "p-ads"), r.rules.map { it.id.value })
        assertEquals(RouteAction.DIRECT, r.defaultAction)
        assertTrue(r.automaticDomestic)
        // Приложения и локальная сеть — свои: это про устройство.
        assertEquals(AppPolicy.AllApps, r.apps)
        assertTrue(r.bypassLan)
        val d = ProviderPolicy.dns(providerDns, p, lists)
        assertEquals(listOf(Layers.DNS_REMOTE, Layers.DNS_LOCAL, "p-doh"), d.rules.map { it.serverId })
        assertEquals("p-doh", d.defaultServerId)
        assertEquals(doh, d.servers.single { it.id == Layers.DNS_REMOTE }.transport, "«через туннель» — резолверу поставщика")
        assertEquals(DnsRoute.DIRECT, d.servers.single { it.id == Layers.DNS_LOCAL }.route)
        // Снять и положить заново — то же; другие свои настройки — другой слой над теми же правилами.
        assertEquals(provider.rules, ProviderPolicy.strip(r).rules)
        assertEquals(providerDns, ProviderPolicy.strip(d))
        val ir = ConfigIr(null, emptyList(), r, d)
        assertEquals(ir, ProviderPolicy.relayer(ir, p, lists))
        val bare = ProviderPolicy.relayer(ir, p.copy(listsEnabled = false), SiteLists.NONE)
        assertEquals(listOf("p-ads"), bare.routing.rules.map { it.id.value })
        assertEquals(providerDns, bare.dns, "имён слоя нет — DNS поставщика как есть")
        // Не взятое у поставщика — не молча (D-05).
        val note = ProviderPolicy.notTaken(provider, p)?.message
        assertTrue(note != null && "выбор приложений" in note && "локальная сеть" in note, note)
        assertNull(ProviderPolicy.notTaken(provider.copy(apps = AppPolicy.AllApps, bypassLan = true), p))
    }

    @Test
    fun bindingTakesConsentAppliesAtOnceAndComesBack() = runBlocking {
        val core = core()
        val id = core.subscriptions.add(URL, null).valueOrNull()!!.id
        val fetcher = Fetcher(clock, doc())
        assertTrue(core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!.applied)
        fun sub() = core.subscriptions.state().valueOrNull()!!.find(id)!!
        fun config() = core.activation.state.activeConfig!!
        fun ruleIds() = config().routing.rules.map { it.id.value }

        // Прислал — видно, но без согласия не действует (D-11).
        assertTrue(sub().providerPolicyOffered)
        assertNull(core.providerPolicyInEffect())
        assertTrue("p-ads" !in ruleIds(), ruleIds().toString())

        // Включил: тело то же, но подписка загружена заново — действуют правила и DNS поставщика.
        val on = core.subscriptions.setProviderPolicy(id, true, fetcher, "test")
        assertIs<ActivationResult.Activated>(on.valueOrNull(), on.toString())
        assertEquals(listOf("p-ads"), ruleIds())
        assertEquals("p-doh", config().dns.defaultServerId)
        assertEquals(RoutingBinding.PROVIDER_ROUTING, sub().binding)
        assertEquals(id, core.providerPolicyInEffect()?.subscription?.id)

        // Режим и реклама сохраняются, но ждут отвязки; свои списки — сразу поверх.
        assertIs<Outcome.Success<*>>(core.userPolicy.change(UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true)))
        assertEquals(listOf("p-ads"), ruleIds())
        assertIs<Outcome.Success<*>>(core.userPolicy.setSiteLists(mapOf(SiteListKind.PROXY to "example.org")))
        assertEquals(listOf("own-proxy-sites", "p-ads"), ruleIds())

        // Поставщик сменил правила — приняты с обновлением, свои по-прежнему поверх.
        clock.advance(60_000)
        fetcher.body = doc(rule = "p-other")
        assertTrue(core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!.applied)
        assertEquals(listOf("own-proxy-sites", "p-other"), ruleIds())

        // Выключил — снова своя политика, с тем, что выбрано, пока действовала поставщика.
        val off = core.subscriptions.setProviderPolicy(id, false, fetcher, "test")
        assertIs<ActivationResult.Activated>(off.valueOrNull(), off.toString())
        assertEquals(listOf("own-proxy-sites", PolicyBuilder.RULE_ADS, PolicyBuilder.RULE_RU_SITES, PolicyBuilder.RULE_RU_IP), ruleIds())
        assertEquals(PolicyBuilder.DNS_REMOTE, config().dns.defaultServerId)
        assertEquals(RoutingBinding.USER_ROUTING, sub().binding)
        assertNull(core.providerPolicyInEffect())
    }

    @Test
    fun failedLoadKeepsBindingAndUnappliedSubscriptionJustStoresIt() = runBlocking {
        val core = core()
        val id = core.subscriptions.add(URL, null).valueOrNull()!!.id
        val fetcher = Fetcher(clock, doc())
        assertTrue(core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!.applied)
        fun binding(of: com.dpsmpx.dppass.core.SubscriptionId) = core.subscriptions.state().valueOrNull()!!.find(of)!!.binding

        // Сети нет — привязка прежняя, правила — пользователя.
        val offline = SubscriptionFetcher { _, _ -> Outcome.failure(DiagCode.SUBSCRIPTION_FETCH_FAILED, "нет сети") }
        assertIs<Outcome.Failure>(core.subscriptions.setProviderPolicy(id, true, offline, "test"))
        assertEquals(RoutingBinding.USER_ROUTING, binding(id))
        assertNull(core.providerPolicyInEffect())

        // Id слоя своих настроек у поставщика — отказ с путём (D-05), привязка прежняя.
        val clash = core.subscriptions.setProviderPolicy(id, true, Fetcher(clock, doc(rule = "own-direct-sites")), "test")
        val e = assertIs<Outcome.Failure>(clash).errors.first()
        assertEquals(DiagCode.ID_DUPLICATE, e.code)
        assertEquals("$.routing.rules[0].id", e.path)
        assertEquals(RoutingBinding.USER_ROUTING, binding(id))

        // Не применённая — привязка записана и действует, когда её применят.
        val other = core.subscriptions.add("https://sub.example.org/x/token-1", null).valueOrNull()!!.id
        assertNull(core.subscriptions.setProviderPolicy(other, true, fetcher, "test").valueOrNull())
        assertEquals(RoutingBinding.PROVIDER_ROUTING, binding(other))
        assertNull(core.providerPolicyInEffect())
        assertTrue(core.subscriptions.refresh(other, fetcher, "test").valueOrNull()!!.applied)
        assertEquals(other, core.providerPolicyInEffect()?.subscription?.id)
        assertEquals(listOf("p-ads"), core.activation.state.activeConfig!!.routing.rules.map { it.id.value })
    }

    private fun list(vararg s: String) = SiteList(s.map { SiteEntry.parse(it).valueOrNull()!! })

    /** Документ DPpass с правилом [rule] — синтетический (TEST-NET, example). */
    private fun doc(rule: String = "p-ads") = """
        {"format":"dppass.config","format_version":2,
         "profiles":[{"id":"t1","name":"T1","server":"203.0.113.41","port":443,
           "protocol":{"type":"trojan","password":"test-password-41"},
           "security":{"type":"tls","server_name":"t1.example.com"}}],
         "routing":{"rules":[{"id":"$rule","action":"block","domain_suffix":["ads.example.com"]}]},
         "dns":{"servers":[{"id":"p-doh","type":"https","url":"https://dns.example.net/dns-query","route":"tunnel"}],"default":"p-doh"}}
    """.trimIndent()

    private companion object {
        const val URL = "https://sub.example.com/api/sub/token-0123456789"
    }
}
