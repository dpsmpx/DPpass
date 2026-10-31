package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.SiteEntry
import com.dpsmpx.dppass.routing.SiteList
import com.dpsmpx.dppass.routing.SiteListKind
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Свои списки сайтов и импорт профиля маршрутизации Happ (D-93). Данные синтетические. */
class HappRoutingTest {
    /** Профиль по публичному описанию формата: поля и значения — свои, синтетические. */
    private val profile = """
        {
          "Name": "Synthetic",
          "GlobalProxy": "true",
          "RemoteDNSType": "DoH",
          "RemoteDNSDomain": "https://dns.example.net/dns-query",
          "RemoteDNSIP": "192.0.2.53",
          "DomesticDNSType": "DoU",
          "DomesticDNSDomain": "",
          "DomesticDNSIP": "198.51.100.53",
          "Geoipurl": "https://files.example.org/geoip.dat",
          "Geositeurl": "https://files.example.org/geosite.dat",
          "LastUpdated": "1792900000",
          "DnsHosts": {"dns.example.net": "192.0.2.53"},
          "DirectSites": ["geosite:category-ru", "example.ru", "regexp:^.*\\.example\\.su$"],
          "DirectIp": ["10.0.0.0/8", "geoip:ru", "geoip:unknown-code"],
          "ProxySites": ["geosite:category-ru", "full:www.example.com"],
          "ProxyIp": ["203.0.113.0/24"],
          "BlockSites": ["ads.example.net"],
          "BlockIp": [],
          "DomainStrategy": "IPIfNonMatch",
          "FakeDNS": "false",
          "SomethingNew": "x"
        }
    """.trimIndent()

    private val unknownCode: (SiteEntry) -> String? = { e -> if (e.text == "geoip:unknown-code") "geoip:unknown-code — такого кода нет в наборе" else null }

    @Test
    fun listsAreTakenEverythingElseIsListedWithReason() {
        val r = HappRouting.parse(profile, unknownCode).valueOrNull()!!
        assertEquals("Synthetic", r.name)
        // geosite:category-ru — и «напрямую», и «через туннель»: берётся в более строгий список.
        assertEquals(listOf("example.ru", "10.0.0.0/8", "geoip:ru"), r.lists.direct.entries.map { it.text })
        assertEquals(listOf("geosite:category-ru", "full:www.example.com", "203.0.113.0/24"), r.lists.proxy.entries.map { it.text })
        assertEquals(listOf("ads.example.net"), r.lists.block.entries.map { it.text })
        val skipped = r.skipped.associate { it.field to it.reason }
        val notTaken = listOf(
            "RemoteDNSType", "RemoteDNSDomain", "RemoteDNSIP", "DomesticDNSType", "DomesticDNSIP",
            "Geoipurl", "Geositeurl", "DnsHosts", "DomainStrategy", "LastUpdated",
        )
        for (field in notTaken) {
            assertTrue(field in skipped, "«$field» — в списке невзятого с причиной: ${r.skipped}")
        }
        assertTrue("GlobalProxy" in skipped)
        assertTrue("DomesticDNSDomain" !in skipped && "FakeDNS" !in skipped && "BlockIp" !in skipped, "пустое и «false» — не настройка, о нём молчать")
        assertTrue(skipped.keys.any { it.startsWith("DirectSites[2]") && "регулярные" in skipped.getValue(it) })
        assertTrue(skipped.keys.any { it.startsWith("DirectIp[2]") }, "кода нет в наборе — не взят")
        assertTrue(skipped.getValue("SomethingNew").startsWith("неизвестное поле"))
        assertTrue(r.lists.validate("p").isEmpty())
    }

    @Test
    fun globalDirectProfileIsNamedNotSilent() {
        // «false» — всё, что не в списках, напрямую: DPpass ведёт это через туннель — смысл меняется, и это видно (D-05).
        for (value in listOf("false", "FALSE", " false ")) {
            val r = HappRouting.parse("""{"ProxySites":["example.com"],"GlobalProxy":"$value"}""").valueOrNull()
            val reason = r?.skipped?.firstOrNull { it.field == "GlobalProxy" }?.reason
            assertTrue(reason != null && "напрямую" in reason && "через туннель" in reason, "GlobalProxy=$value: $reason")
        }
        val provider = HappRouting.provider("""{"ProxySites":["example.com"],"GlobalProxy":"false"}""").valueOrNull()
        assertTrue(provider?.skipped?.any { it.field == "GlobalProxy" } == true, "и у профиля поставщика (D-94)")
        // Пустое — не настройка.
        assertTrue(HappRouting.parse("""{"ProxySites":["example.com"],"GlobalProxy":""}""").valueOrNull()?.skipped?.isEmpty() == true)
    }

    @Test
    fun linksAddAndOnaddInBothBase64Alphabets() {
        val json = """{"ProxySites":["example.com"],"BlockIp":["198.51.100.0/24"]}"""
        val std = Base64.getEncoder().encodeToString(json.toByteArray())
        val url = Base64.getUrlEncoder().withoutPadding().encodeToString(json.toByteArray())
        for (link in listOf("happ://routing/add/$std", "happ://routing/onadd/$url", "HAPP://routing/ADD/$std")) {
            assertTrue(HappRouting.looksLike(link))
            val r = HappRouting.parse(link).valueOrNull()
            assertEquals(listOf("example.com"), r?.lists?.proxy?.entries?.map { it.text }, link)
            assertEquals(listOf("198.51.100.0/24"), r?.lists?.block?.entries?.map { it.text })
        }
        val off = HappRouting.parse("happ://routing/off")
        assertTrue(off is Outcome.Failure && off.errors.first().code == DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "выключить маршрутизацию ссылкой — нельзя")
        assertTrue(HappRouting.parse("happ://routing/add/@@@") is Outcome.Failure)
        val empty = HappRouting.parse("""{"DirectSites":["regexp:x"],"GlobalProxy":"true"}""")
        assertTrue(empty is Outcome.Failure && empty.errors.first().code == DiagCode.SUBSCRIPTION_NO_USABLE_SERVERS, "нечего взять — отказ с примером причины")
    }

    @Test
    fun classifierRecognizesProfilesAndRefusesEncryptedLinks() {
        assertTrue(ImportClassifier.classify(profile) is ImportKind.HappRouting)
        assertTrue(ImportClassifier.classify("happ://routing/add/e30=") is ImportKind.HappRouting)
        val crypt = ImportClassifier.classify("happ://crypt5/SYNTHETICPAYLOAD")
        assertTrue(crypt is ImportKind.Unrecognized && crypt.reason?.message?.contains("D-11") == true, "зашифрованные — не открываются, с причиной")
        assertTrue(ImportClassifier.classify("""{"unrelated": 1}""") is ImportKind.Unrecognized, "JSON без списков Happ — не профиль")
    }

    @Test
    fun policyV2KeepsListsAndV1StillReads() {
        val blobs = InMemoryBlobStore()
        val store = PolicyStore(blobs, Quarantine(blobs, ManualClock(1)))
        val lists = SiteLists(direct = list("example.ru", "geoip:ru"), proxy = list("full:www.example.com"), block = list("ads.example.net", "203.0.113.0/24"))
        val p = UserPolicy(mode = RoutingMode.RU_DIRECT, lists = lists)
        assertTrue(store.save(p) is Outcome.Success)
        assertEquals(p, store.load().valueOrNull())
        val v1 = """{"format":"dppass.policy","format_version":1,"mode":"auto","block_ads":true,"bypass_lan":true,""" +
            """"apps":{"mode":"all","packages":[]},"dns":"quad9"}"""
        val old = PolicyCodec.read(v1).valueOrNull()!!
        assertEquals(SiteLists.NONE, old.lists, "версия 1 — без своих списков")
        assertEquals(RoutingMode.AUTO, old.mode)
        val dup = PolicyCodec.write(p).replace("\"proxy\":[\"full:www.example.com\"]", "\"proxy\":[\"example.ru\"]")
        assertTrue(PolicyCodec.read(dup) is Outcome.Failure, "запись в двух списках — порча, не «ближайшее похожее»")
        val notNormal = PolicyCodec.write(p).replace("\"ads.example.net\"", "\"ADS.example.net\"")
        assertTrue(PolicyCodec.read(notNormal) is Outcome.Failure)
    }

    @Test
    fun ownListsComeBeforeModeRulesAndSteerDns() {
        val p = UserPolicy(
            mode = RoutingMode.RU_DIRECT,
            blockAds = true,
            lists = SiteLists(direct = list("example.com"), proxy = list("example.ru", "198.51.100.0/24"), block = list("ads.example.net")),
        )
        val rules = PolicyBuilder.routing(p).rules
        assertEquals(
            listOf(
                "own-block-sites", "own-proxy-sites", "own-proxy-ip", "own-direct-sites",
                PolicyBuilder.RULE_ADS, PolicyBuilder.RULE_RU_SITES, PolicyBuilder.RULE_RU_IP,
            ),
            rules.map { it.id.value },
        )
        assertEquals(RouteAction.PROXY, rules[1].action)
        val dns = PolicyBuilder.dns(p)
        assertEquals(listOf(PolicyBuilder.DNS_REMOTE, PolicyBuilder.DNS_LOCAL, PolicyBuilder.DNS_LOCAL), dns.rules.map { it.serverId })
        // Российский сайт «через туннель» — и имя через туннель, до правила category-ru.
        assertEquals(listOf(DomainMatcher.Suffix("example.ru")), dns.rules.first().domains)
        // Всё через туннель, «напрямую» — пример: свой резолвер для прямых имён появляется только ради них.
        val all = PolicyBuilder.dns(UserPolicy(lists = SiteLists(direct = list("example.com"))))
        assertEquals(listOf(PolicyBuilder.DNS_LOCAL), all.rules.map { it.serverId })
        assertEquals(1, PolicyBuilder.dns(UserPolicy()).servers.size, "без списков — как прежде")
    }

    @Test
    fun mergingAnImportIntoOwnListsKeepsOneListPerEntry() {
        val mine = SiteLists(direct = list("example.com"))
        val r = HappRouting.parse("""{"ProxySites":["example.com","example.org"]}""").valueOrNull()!!
        val merged = mine.merge(r.lists)
        assertEquals(SiteList(), merged.direct)
        assertEquals(listOf("example.com", "example.org"), merged[SiteListKind.PROXY].entries.map { it.text })
    }

    @Test
    fun serviceSetsListsFromTextAndAddsImportsAsOneTransaction() = runBlocking {
        val blobs = InMemoryBlobStore()
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, ManualClock(1_000_000), "com.dpsmpx.dppass", PlatformTraits(true))
        assertTrue(core.userPolicy.setSiteLists(mapOf(SiteListKind.DIRECT to "example.com\n# заметка\ngeoip:ru")) is Outcome.Success)
        assertEquals(listOf("example.com", "geoip:ru"), core.userPolicy.currentOrDefault().lists.direct.entries.map { it.text })
        // Неверная строка — отказ с номером строки, прежние списки на месте.
        val bad = core.userPolicy.setSiteLists(mapOf(SiteListKind.BLOCK to "ok.example.net\nregexp:x"))
        assertTrue(bad is Outcome.Failure && bad.errors.single().path == "${PolicyBuilder.LISTS_PATH}.block[2]")
        assertEquals(SiteList(), core.userPolicy.currentOrDefault().lists.block)
        // Та же запись в двух списках из правки — отказ.
        val dup = core.userPolicy.setSiteLists(mapOf(SiteListKind.PROXY to "example.com"))
        assertTrue(dup is Outcome.Failure && dup.errors.single().code == DiagCode.RULE_DUPLICATE)
        // Импорт добавляет и переносит: example.com — «через туннель», как в профиле.
        val happ = HappRouting.parse("""{"ProxySites":["example.com"],"BlockSites":["ads.example.net"]}""").valueOrNull()!!
        assertTrue(core.userPolicy.addSiteLists(happ.lists) is Outcome.Success)
        val now = core.userPolicy.currentOrDefault().lists
        assertEquals(listOf("geoip:ru"), now.direct.entries.map { it.text })
        assertEquals(listOf("example.com"), now.proxy.entries.map { it.text })
        assertEquals(listOf("ads.example.net"), now.block.entries.map { it.text })
        assertEquals(now, PolicyStore(blobs, Quarantine(blobs, ManualClock(2))).load().valueOrNull()?.lists, "на диске")
    }

    private fun list(vararg s: String) = SiteList(s.map { SiteEntry.parse(it).valueOrNull()!! })
}
