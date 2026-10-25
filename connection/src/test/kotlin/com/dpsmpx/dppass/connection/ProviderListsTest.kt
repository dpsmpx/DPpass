package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.routing.SiteListsChange
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.subscriptions.FetchPolicy
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionRequest
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Списки поставщика рядом со своими, свои — поверх и с переключателем (D-94). Данные синтетические. */
class ProviderListsTest {
    private val clock = ManualClock(1_000_000)
    private val blobs = InMemoryBlobStore()

    private fun core() = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))

    private class Fetcher(private val clock: ManualClock, var headers: Map<String, String>) : SubscriptionFetcher {
        override suspend fun fetch(request: SubscriptionRequest, policy: FetchPolicy) =
            Outcome.Success(FetchedPayload(LINKS.toByteArray(), headers, clock.nowMillis()))
    }

    @Test
    fun providerProfileIsLinkJsonOrBase64AndOffMeansNoLists() {
        val json = """{"Name":"P","DirectSites":["example.ru"],"ProxyIp":["198.51.100.0/24"]}"""
        val b64 = Base64.getEncoder().encodeToString(json.toByteArray())
        for (text in listOf(json, b64, "happ://routing/onadd/$b64")) {
            val r = HappRouting.provider(text).valueOrNull()
            assertNotNull(r, text)
            assertEquals(listOf("example.ru"), r.lists.direct.entries.map { it.text })
            assertEquals(listOf("198.51.100.0/24"), r.lists.proxy.entries.map { it.text })
        }
        // Поставщик убирает списки: off и профиль без записей — «списков нет», не отказ.
        assertEquals(SiteLists.NONE, HappRouting.provider("happ://routing/off").valueOrNull()?.lists)
        assertEquals(SiteLists.NONE, HappRouting.provider("""{"Name":"P"}""").valueOrNull()?.lists)
        // Импорт рукой — по-прежнему отказ: маршрутизацию пользователя ссылка не выключает (D-11).
        assertIs<Outcome.Failure>(HappRouting.parse("happ://routing/off"))
        assertIs<Outcome.Failure>(HappRouting.provider("not a profile"))
    }

    @Test
    fun ownListsOverProviderOverAdsAndModeAndOwnCanBeSwitchedOff() {
        val provider = SiteLists(direct = list("example.com", "geoip:ru"), proxy = list("example.ru"))
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true, lists = SiteLists(proxy = list("example.com"), direct = list("example.org")))
        assertEquals(
            listOf(
                "own-proxy-sites", "own-direct-sites", "provider-proxy-sites", "provider-direct-sites", "provider-direct-ip",
                PolicyBuilder.RULE_ADS, PolicyBuilder.RULE_RU_SITES, PolicyBuilder.RULE_RU_IP,
            ),
            PolicyBuilder.routing(p, provider).rules.map { it.id.value },
        )
        // Свой «через туннель» сильнее «напрямую» поставщика — и в DNS: первое правило решает.
        val dns = PolicyBuilder.dns(p, provider)
        assertEquals(
            listOf(PolicyBuilder.DNS_REMOTE, PolicyBuilder.DNS_LOCAL, PolicyBuilder.DNS_REMOTE, PolicyBuilder.DNS_LOCAL, PolicyBuilder.DNS_LOCAL),
            dns.rules.map { it.serverId },
        )
        assertEquals(listOf(DomainMatcher.Suffix("example.com")), dns.rules.first().domains)
        // Свои выключены — правил не дают, но хранятся; списки поставщика — на месте.
        val off = p.copy(listsEnabled = false)
        assertEquals(
            listOf(
                "provider-proxy-sites", "provider-direct-sites", "provider-direct-ip",
                PolicyBuilder.RULE_ADS, PolicyBuilder.RULE_RU_SITES, PolicyBuilder.RULE_RU_IP,
            ),
            PolicyBuilder.routing(off, provider).rules.map { it.id.value },
        )
        assertEquals(PolicyBuilder.routing(UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true)), PolicyBuilder.routing(off))
    }

    @Test
    fun policyV3KeepsSwitchV2ReadsListsAsEnabled() {
        val store = PolicyStore(blobs, Quarantine(blobs, clock))
        val p = UserPolicy(lists = SiteLists(direct = list("example.ru")), listsEnabled = false)
        assertTrue(store.save(p) is Outcome.Success)
        assertEquals(p, store.load().valueOrNull())
        val v2 = """{"format":"dppass.policy","format_version":2,"mode":"auto","block_ads":false,"bypass_lan":true,""" +
            """"apps":{"mode":"all","packages":[]},"dns":"quad9","lists":{"block":[],"proxy":[],"direct":["example.ru"]}}"""
        val old = PolicyCodec.read(v2).valueOrNull()!!
        assertTrue(old.listsEnabled, "до D-94 свои списки действовали всегда")
        val v2With3 = v2.replace("\"dns\":\"quad9\"", "\"dns\":\"quad9\",\"lists_enabled\":false")
        assertIs<Outcome.Failure>(PolicyCodec.read(v2With3), "поле версии 3 в версии 2 — порча")
    }

    @Test
    fun changeShowsAddedRemovedAndMovedEntries() {
        val old = SiteLists(direct = list("example.com", "example.org"), block = list("ads.example.net"))
        val new = SiteLists(direct = list("example.org"), proxy = list("example.com", "example.ru"), block = list("ads.example.net"))
        val c = SiteListsChange.between(old, new)
        assertEquals(listOf("example.com", "example.ru"), c.added.proxy.entries.map { it.text })
        assertEquals(listOf("example.com"), c.removed.direct.entries.map { it.text }, "перешла в другой список — убрана из прежнего")
        assertTrue(c.added.block.isEmpty && c.removed.block.isEmpty)
        assertTrue(SiteListsChange.between(new, new).isEmpty)
    }

    @Test
    fun providerListsAreKeptAppliedOnlyWithConsentAndFollowUpdates() = runBlocking {
        val core = core()
        val id = core.subscriptions.add(URL, null).valueOrNull()!!.id
        val fetcher = Fetcher(clock, mapOf("routing" to link("""{"Name":"P","DirectSites":["example.ru"]}""")))
        assertTrue(core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!.applied)
        fun sub() = core.subscriptions.state().valueOrNull()!!.find(id)!!
        fun ruleIds() = core.activation.state.activeConfig!!.routing.rules.map { it.id.value }

        // Сохранены рядом, но без согласия не действуют (D-11).
        assertNotNull(sub().providerProfile)
        assertTrue(ruleIds().none { it.startsWith("provider-") }, ruleIds().toString())
        val view = core.providerLists(sub())!!
        assertFalse(view.inUse)
        assertTrue(view.applied)
        assertEquals(listOf("example.ru"), view.profile!!.lists.direct.entries.map { it.text })

        // Включил — действуют, согласие записано.
        val on = core.subscriptions.setUseProviderLists(id, true)
        assertIs<ActivationResult.Activated>(on.valueOrNull(), on.toString())
        assertEquals(listOf("provider-direct-sites"), ruleIds())
        assertTrue(sub().useProviderLists)

        // Поставщик прислал другие списки — применены с обновлением, и видно, что изменилось.
        clock.advance(60_000)
        fetcher.headers = mapOf("routing" to link("""{"Name":"P","DirectSites":["example.org"],"BlockSites":["ads.example.net"]}"""))
        val run = core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!
        assertTrue(run.applied, run.diagnostics.joinToString { it.render() })
        assertEquals(listOf("provider-block-sites", "provider-direct-sites"), ruleIds())
        val change = core.providerLists(sub())!!.change!!
        assertEquals(listOf("example.org"), change.added.direct.entries.map { it.text })
        assertEquals(listOf("example.ru"), change.removed.direct.entries.map { it.text })
        assertEquals(listOf("ads.example.net"), change.added.block.entries.map { it.text })

        // Свои — поверх; выключил свои — списки поставщика остались.
        assertTrue(core.userPolicy.setSiteLists(mapOf(SiteListKind.PROXY to "example.org")) is Outcome.Success)
        assertEquals(listOf("own-proxy-sites", "provider-block-sites", "provider-direct-sites"), ruleIds())
        assertTrue(core.userPolicy.setListsEnabled(false) is Outcome.Success)
        assertEquals(listOf("provider-block-sites", "provider-direct-sites"), ruleIds())
        assertEquals(listOf("example.org"), core.userPolicy.currentOrDefault().lists.proxy.entries.map { it.text }, "выключенные свои хранятся")

        // Не разобранный профиль не заменяет прежний: сервера обновляются, списки — прежние.
        clock.advance(60_000)
        val before = sub().providerProfile
        fetcher.headers = mapOf("routing" to "happ://routing/onadd/%%%")
        val broken = core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!
        assertTrue(broken.diagnostics.any { it.code == DiagCode.SUBSCRIPTION_METADATA_INVALID && it.message.startsWith("routing:") })
        assertEquals(before, sub().providerProfile)
        assertEquals(listOf("provider-block-sites", "provider-direct-sites"), ruleIds())

        // Выключил списки поставщика — их правил нет, профиль хранится.
        assertTrue(core.subscriptions.setUseProviderLists(id, false) is Outcome.Success)
        assertTrue(ruleIds().isEmpty(), ruleIds().toString())
        assertNotNull(sub().providerProfile)
        // Без профиля у поставщика экрана нет.
        val other = core.subscriptions.add("https://sub.example.org/x/token-1", null).valueOrNull()!!
        assertNull(core.providerLists(other))
    }

    private fun link(json: String) = "happ://routing/onadd/" + Base64.getEncoder().encodeToString(json.toByteArray())

    private fun list(vararg s: String) = SiteList(s.map { SiteEntry.parse(it).valueOrNull()!! })

    private companion object {
        const val URL = "https://sub.example.com/api/sub/token-0123456789"
        const val LINKS = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#A\n" +
            "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"
    }
}
