package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DnsValidator
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingValidator
import com.dpsmpx.dppass.routing.TableGeoResolver
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Политика пользователя → маршрутизация и DNS (D-38). */
class PolicyBuilderTest {
    private val geo = TableGeoResolver(
        sites = mapOf(
            PolicyBuilder.GEOSITE_RU to listOf(DomainMatcher.Suffix("example.ru")),
            PolicyBuilder.GEOSITE_ADS to listOf(DomainMatcher.Suffix("ads.example.ru"), DomainMatcher.Suffix("ads.example.com")),
        ),
        ips = mapOf(PolicyBuilder.GEOIP_RU to listOf(Cidr.parse("198.51.100.0/24")!!.cidr)),
    )

    private fun decide(p: UserPolicy, q: RouteQuery) = RouteEvaluator(PolicyBuilder.routing(p), geo).decide(q).action

    @Test
    fun defaultIsEverythingThroughTunnelWithDohLikeD36() {
        val r = PolicyBuilder.routing(UserPolicy.DEFAULT)
        assertTrue(r.rules.isEmpty())
        assertEquals(RouteAction.PROXY, r.defaultAction)
        assertTrue(r.bypassLan)
        assertEquals(AppPolicy.AllApps, r.apps)
        val dns = PolicyBuilder.dns(UserPolicy.DEFAULT)
        assertEquals(DnsTransport.Https("https://1.1.1.1/dns-query"), dns.servers.single().transport)
        assertEquals(DnsRoute.TUNNEL, dns.servers.single().route)
        assertEquals(RouteAction.PROXY, decide(UserPolicy.DEFAULT, RouteQuery(domain = "www.example.ru")))
    }

    @Test
    fun russianDirectSendsRussianSitesAndAddressesPastTheTunnel() {
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT)
        assertEquals(RouteAction.DIRECT, decide(p, RouteQuery(domain = "shop.example.ru")))
        assertEquals(RouteAction.DIRECT, decide(p, RouteQuery(ip = IpAddress.parse("198.51.100.7"))))
        assertEquals(RouteAction.PROXY, decide(p, RouteQuery(domain = "www.example.com", ip = IpAddress.parse("203.0.113.1"))))
        // Имена российских сайтов — системным резолвером мимо туннеля; остальное — DoH через туннель.
        val dns = PolicyBuilder.dns(p)
        assertEquals(PolicyBuilder.DNS_REMOTE, dns.defaultServerId)
        val local = dns.server(dns.rules.single().serverId)!!
        assertEquals(DnsTransport.System to DnsRoute.DIRECT, local.transport to local.route)
        assertEquals(listOf(PolicyBuilder.GEOSITE_RU), dns.rules.single().geoSites)
        assertTrue(DnsValidator.validate(dns).isEmpty(), "сервер по умолчанию — через туннель: утечки нет")
    }

    @Test
    fun adsAreBlockedFirstEvenOnRussianSites() {
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true)
        assertEquals(PolicyBuilder.RULE_ADS, PolicyBuilder.routing(p).rules.first().id.value)
        assertEquals(RouteAction.BLOCK, decide(p, RouteQuery(domain = "ads.example.ru")))
        assertEquals(RouteAction.BLOCK, decide(p, RouteQuery(domain = "ads.example.com")))
        assertTrue(RoutingValidator.validate(PolicyBuilder.routing(p)).isEmpty())
    }

    @Test
    fun appsAndLan() {
        val except = PolicyBuilder.routing(UserPolicy(appMode = AppMode.EXCEPT, apps = setOf("com.example.bank")))
        assertEquals(AppPolicy.ExceptApps(setOf("com.example.bank")), except.apps)
        assertEquals(RouteAction.DIRECT, RouteEvaluator(except).decide(RouteQuery(domain = "a.example.com", packageName = "com.example.bank")).action)
        assertEquals(
            AppPolicy.OnlyApps(setOf("org.example.browser")),
            PolicyBuilder.routing(UserPolicy(appMode = AppMode.ONLY, apps = setOf("org.example.browser"))).apps,
        )
        assertEquals(false, PolicyBuilder.routing(UserPolicy(bypassLan = false)).bypassLan)
        // «Только выбранные» без приложений — ошибка: VpnService пустил бы в туннель все.
        assertEquals(listOf(DiagCode.APP_POLICY_CONFLICT), PolicyBuilder.validate(UserPolicy(appMode = AppMode.ONLY)).map { it.code })
        assertEquals(listOf(DiagCode.PACKAGE_INVALID), PolicyBuilder.validate(UserPolicy(apps = setOf("not a package"))).map { it.code })
    }

    @Test
    fun autoModeEnablesDomesticSplit() {
        val p = UserPolicy(mode = RoutingMode.AUTO)
        val routing = PolicyBuilder.routing(p)
        // Автосплит включён; явных ru-правил нет — отечественное уводит запасное правило (D-45).
        assertTrue(routing.automaticDomestic)
        assertTrue(routing.rules.none { it.id.value == PolicyBuilder.RULE_RU_SITES })
        // Отечественное — напрямую само, без выбора сайтов; зарубежное — в туннель.
        assertEquals(RouteAction.DIRECT, decide(p, RouteQuery(domain = "shop.example.ru")))
        assertEquals(RouteAction.DIRECT, decide(p, RouteQuery(ip = IpAddress.parse("198.51.100.7"))))
        assertEquals(RouteAction.PROXY, decide(p, RouteQuery(domain = "www.example.com", ip = IpAddress.parse("203.0.113.1"))))
        // Имена российских сайтов — системным резолвером, как в RU_DIRECT; утечки нет.
        val dns = PolicyBuilder.dns(p)
        assertEquals(listOf(PolicyBuilder.GEOSITE_RU), dns.rules.single().geoSites)
        assertTrue(DnsValidator.validate(dns).isEmpty())
    }

    @Test
    fun dnsProviderIsDohByIpThroughTunnel() {
        for (provider in DnsProvider.entries) {
            val dns = PolicyBuilder.dns(UserPolicy(dns = provider))
            val url = (dns.servers.first().transport as DnsTransport.Https).url
            assertTrue(url.startsWith("https://") && url.removePrefix("https://").substringBefore('/').all { it.isDigit() || it == '.' }, url)
        }
    }
}

class PolicyStoreTest {
    private val clock = ManualClock(1_000)

    @Test
    fun roundTripAndDefault() {
        val blobs = InMemoryBlobStore()
        val store = PolicyStore(blobs, Quarantine(blobs, clock))
        assertEquals(UserPolicy.DEFAULT, store.load().valueOrNull())
        val p = UserPolicy(
            RoutingMode.RU_DIRECT,
            blockAds = true,
            bypassLan = false,
            appMode = AppMode.EXCEPT,
            apps = setOf("com.example.bank"),
            dns = DnsProvider.QUAD9,
        )
        assertTrue(store.save(p).isSuccess)
        assertEquals(p, PolicyStore(blobs, Quarantine(blobs, clock)).load().valueOrNull())
    }

    @Test
    fun corruptedPolicyGoesToQuarantine() {
        val blobs = InMemoryBlobStore()
        blobs.write(PolicyStore.KEY, """{"format":"dppass.policy","format_version":1,"mode":"everything"}""".toByteArray())
        val r = PolicyStore(blobs, Quarantine(blobs, clock)).load()
        assertEquals(UserPolicy.DEFAULT, r.valueOrNull())
        assertTrue(r.diagnostics.any { it.code == DiagCode.STORAGE_CORRUPTED })
        assertTrue(Quarantine(blobs, clock).list().valueOrNull()!!.isNotEmpty())
    }
}

class PolicyServiceTest {
    private val blobs = InMemoryBlobStore()
    private fun core() = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, ManualClock(1_000_000), "com.dpsmpx.dppass", PlatformTraits(true))
    private fun doc(name: String) = File(System.getProperty("dppass.repoRoot"), "tests/data/configs/$name").readText()

    @Test
    fun changingPolicyReactivatesActiveServers() = runBlocking {
        val core = core()
        assertIs<ActivationResult.Activated>(core.importAndActivate(doc("valid-minimal.json")).valueOrNull())
        val before = core.activation.state
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT)
        val r = core.userPolicy.change(p)
        assertIs<ActivationResult.Activated>(r.valueOrNull())
        val after = core.activation.state
        assertEquals(before.activeConfig!!.profiles, after.activeConfig!!.profiles, "серверы те же")
        assertEquals(before.active!!.source, after.active!!.source, "источник тот же")
        assertEquals(PolicyBuilder.routing(p), after.activeConfig.routing)
        assertNotEquals(before.activeConfig.routing, after.activeConfig.routing)
        // Новый процесс — та же политика.
        assertEquals(p, core().userPolicy.current().valueOrNull())
    }

    @Test
    fun invalidPolicyIsRejectedAndNothingChanges() = runBlocking {
        val core = core()
        core.importAndActivate(doc("valid-minimal.json"))
        val before = core.activation.state.active
        val r = core.userPolicy.change(UserPolicy(appMode = AppMode.ONLY))
        assertIs<Outcome.Failure>(r)
        assertEquals(before, core.activation.state.active)
        assertEquals(UserPolicy.DEFAULT, core.userPolicy.currentOrDefault())
    }

    @Test
    fun ownDocumentRoutingIsTheBaseUntilPolicyChanges() {
        val core = core()
        runBlocking { core.importAndActivate(doc("valid-minimal.json")) }
        val own = core.activation.state.activeConfig!!
        assertEquals(own, core.userPolicy.baseFor(core.activation.state))
        assertEquals(PolicyBuilder.ir(UserPolicy.DEFAULT), core.userPolicy.baseFor(ActivationState.EMPTY))
    }
}
