package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Свои списки сайтов (D-93): записи, списки, порядок и смысл правил. */
class SiteListsTest {
    private fun entry(s: String) = SiteEntry.parse(s).valueOrNull()?.text

    @Test
    fun entriesAreNormalized() {
        assertEquals("example.com", entry("Example.COM"))
        assertEquals("example.com", entry("*.example.com"), "*. и . в начале — то же, что домен с поддоменами")
        assertEquals("example.com", entry(".example.com"))
        assertEquals("example.com", entry("domain:example.com"), "как пишут Xray и другие клиенты")
        assertEquals("full:www.example.com", entry("full:www.example.com"))
        assertEquals("keyword:example", entry("keyword:Example"))
        assertEquals("geosite:category-ru", entry("geosite:Category-RU"))
        assertEquals("geoip:ru", entry("GEOIP:ru"))
        assertEquals("203.0.113.7", entry("203.0.113.7"), "один адрес — без /32")
        assertEquals("198.51.100.0/24", entry("198.51.100.9/24"), "биты узла отбрасываются")
        assertEquals("2001:db8::/32", entry("2001:db8::/32"))
    }

    @Test
    fun badEntriesAreRefusedWithReason() {
        val cases = mapOf(
            "regexp:^ex.*$" to DiagCode.CAPABILITY_FEATURE_UNSUPPORTED,
            "geosite:" to DiagCode.GEO_CODE_INVALID,
            "geoip:Ру" to DiagCode.GEO_CODE_INVALID,
            "300.1.2.3/8" to DiagCode.CIDR_INVALID,
            "10.0.0.0/33" to DiagCode.CIDR_INVALID,
            "not a domain" to DiagCode.DOMAIN_INVALID,
            "keyword:a" to DiagCode.DOMAIN_INVALID,
            // Имена в DNS — латиница (кириллица — как xn--…): такое слово не совпало бы ни с чем (D-05).
            "keyword:яндекс" to DiagCode.DOMAIN_INVALID,
            "keyword:straße" to DiagCode.DOMAIN_INVALID,
            "full:" to DiagCode.DOMAIN_INVALID,
        )
        for ((text, code) in cases) {
            val r = SiteEntry.parse(text)
            assertTrue(r is Outcome.Failure && r.errors.first().code == code, "$text → $r")
        }
    }

    @Test
    fun listParseKeepsOrderDropsRepeatsAndNamesTheLine() {
        val ok = SiteList.parse("# мои\nexample.com\n\nEXAMPLE.com\ngeoip:ru\n", "policy.lists.direct").valueOrNull()!!
        assertEquals(listOf("example.com", "geoip:ru"), ok.entries.map { it.text })
        val bad = SiteList.parse("example.com\nregexp:x\nexample.org\nnot a domain", "policy.lists.proxy")
        assertTrue(bad is Outcome.Failure)
        // Ошибка — с номером строки, список целиком не принят.
        assertEquals(listOf("policy.lists.proxy[2]", "policy.lists.proxy[4]"), bad.errors.map { it.path })
        assertTrue(bad.errors.first().message.startsWith("строка 2:"))
        val many = (1..SiteList.MAX_ENTRIES + 1).joinToString("\n") { "s$it.example.com" }
        assertTrue(SiteList.parse(many, "p").let { it is Outcome.Failure && it.errors.single().code == DiagCode.LIMIT_EXCEEDED })
    }

    @Test
    fun anEntryLivesInOneListOnly() {
        val lists = SiteLists(direct = list("example.com"), proxy = list("example.com", "example.org"))
        val problems = lists.validate("policy.lists")
        assertEquals(1, problems.size)
        assertEquals(DiagCode.RULE_DUPLICATE, problems.single().code)
    }

    @Test
    fun mergeMovesAnEntryToWhereTheImportPutsIt() {
        val mine = SiteLists(direct = list("example.com", "geoip:ru"), block = list("ads.example.net"))
        val imported = SiteLists(proxy = list("example.com", "example.org"), block = list("ads.example.net"))
        val merged = mine.merge(imported)
        assertEquals(listOf("geoip:ru"), merged.direct.entries.map { it.text })
        assertEquals(listOf("example.com", "example.org"), merged.proxy.entries.map { it.text })
        assertEquals(listOf("ads.example.net"), merged.block.entries.map { it.text }, "без повторов")
        assertTrue(merged.validate("p").isEmpty())
    }

    @Test
    fun namesAndAddressesAreSeparateConditionsOfTheList() {
        val l = list("example.com", "full:www.example.org", "keyword:tracker", "geosite:category-ru", "203.0.113.0/24", "geoip:ru")
        val names = l.names()!!
        assertEquals(3, names.domains.size)
        assertEquals(listOf("category-ru"), names.geoSites)
        assertTrue(names.ipCidrs.isEmpty(), "по имени и по адресу — разные правила: у одного правила это было бы И")
        val ips = l.addresses()!!
        assertEquals(listOf("ru"), ips.geoIps)
        assertEquals(1, ips.ipCidrs.size)
        assertEquals(null, list("example.com").addresses())
    }

    @Test
    fun blockWinsOverTunnelAndTunnelOverDirectWhenListsOverlap() {
        // Домен «напрямую», а его поддомен — «через туннель», а адрес — «блокировать»: решает порядок.
        val lists = SiteLists(direct = list("example.com"), proxy = list("full:www.example.com"), block = list("203.0.113.0/24"))
        val rules = SiteLists.ORDER.flatMap { k ->
            listOfNotNull(
                lists[k].names()?.let { Rule(RuleId("${k.wire}-n"), it, k.action) },
                lists[k].addresses()?.let { Rule(RuleId("${k.wire}-a"), it, k.action) },
            )
        }
        val e = RouteEvaluator(RoutingPolicy(rules = rules, defaultAction = RouteAction.PROXY))
        assertEquals(RouteAction.PROXY, e.decide(RouteQuery(domain = "www.example.com")).action)
        assertEquals(RouteAction.DIRECT, e.decide(RouteQuery(domain = "cdn.example.com")).action)
        assertEquals(RouteAction.BLOCK, e.decide(RouteQuery(domain = "cdn.example.com", ip = IpAddress.parse("203.0.113.5"))).action)
    }

    private fun list(vararg s: String) = SiteList(s.map { SiteEntry.parse(it).valueOrNull()!! })
}
