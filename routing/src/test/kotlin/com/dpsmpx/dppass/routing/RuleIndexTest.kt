package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.PortRange
import com.dpsmpx.dppass.core.RuleId
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Индекс правил по имени (D-89): те же решения, что у перебора, и быстрее на многих правилах. */
class RuleIndexTest {
    private val labels = listOf("example", "test", "video", "ads", "mail", "cdn", "a", "b", "ru", "com", "org")
    private val geo = TableGeoResolver(
        sites = mapOf("site-a" to listOf(DomainMatcher.Suffix("example.org")), "site-b" to listOf(DomainMatcher.Keyword("cdn"))),
        ips = mapOf("ip-a" to listOf(Cidr.parse("198.51.100.0/24")!!.cidr)),
    )

    private fun name(r: Random): String = List(1 + r.nextInt(4)) { labels[r.nextInt(labels.size)] }.joinToString(".")

    private fun matcher(r: Random): DomainMatcher = when (r.nextInt(10)) {
        0 -> DomainMatcher.Keyword(labels[r.nextInt(labels.size)])
        1, 2, 3 -> DomainMatcher.Full(name(r))
        // Необычные суффиксы — пустой и с точкой впереди: индекс не должен их терять.
        4 -> DomainMatcher.Suffix(if (r.nextBoolean()) "" else "." + name(r))
        else -> DomainMatcher.Suffix(name(r))
    }

    private fun conditions(r: Random): Conditions {
        while (true) {
            val c = Conditions(
                domains = if (r.nextInt(3) > 0) List(1 + r.nextInt(3)) { matcher(r) } else emptyList(),
                ipCidrs = if (r.nextInt(5) == 0) listOf(Cidr.parse("203.0.113.0/25")!!.cidr) else emptyList(),
                geoSites = if (r.nextInt(8) == 0) listOf(if (r.nextBoolean()) "site-a" else "site-b") else emptyList(),
                geoIps = if (r.nextInt(10) == 0) listOf("ip-a") else emptyList(),
                protocols = if (r.nextInt(6) == 0) setOf(TransportProtocol.UDP) else emptySet(),
                ports = if (r.nextInt(6) == 0) listOf(PortRange(443, 443)) else emptyList(),
                networks = if (r.nextInt(8) == 0) setOf(NetworkKind.MOBILE) else emptySet(),
            )
            if (!c.isEmpty) return c
        }
    }

    private fun query(r: Random) = RouteQuery(
        domain = if (r.nextInt(6) > 0) (if (r.nextInt(10) == 0) "." + name(r) else name(r)) else null,
        ip = when (r.nextInt(4)) {
            0 -> IpAddress.parse("203.0.113.${r.nextInt(256)}")
            1 -> IpAddress.parse("198.51.100.${r.nextInt(256)}")
            else -> null
        },
        port = if (r.nextBoolean()) 443 else 80,
        protocol = if (r.nextBoolean()) TransportProtocol.UDP else TransportProtocol.TCP,
        network = if (r.nextBoolean()) NetworkKind.MOBILE else NetworkKind.WIFI,
    )

    @Test
    fun sameDecisionsAsScanningAllRules() {
        val r = Random(20261025)
        repeat(60) { round ->
            val rules = List(1 + r.nextInt(80)) { i -> Rule(RuleId("r$i"), conditions(r), RouteAction.entries[r.nextInt(3)]) }
            val policy = RoutingPolicy(rules = rules, defaultAction = RouteAction.PROXY)
            val indexed = RouteEvaluator(policy, geo)
            val scan = RouteEvaluator(policy, geo, indexed = false)
            repeat(300) {
                val q = query(r)
                assertEquals(scan.decide(q), indexed.decide(q), "круг $round, запрос $q")
            }
        }
    }

    @Test
    fun manySuffixRulesNoLongerScanEveryRule() {
        // Как bench (PERFORMANCE_BUDGET.md, §3): 4096 правил domain_suffix, имена мимо всех.
        val rules = List(4096) { i -> Rule(RuleId("r$i"), Conditions(domains = listOf(DomainMatcher.Suffix("site$i.example"))), RouteAction.DIRECT) }
        val policy = RoutingPolicy(rules = rules)
        val indexed = RouteEvaluator(policy)
        val scan = RouteEvaluator(policy, indexed = false)
        val queries = List(2000) { RouteQuery(domain = "host$it.example.org") }
        repeat(3) { queries.forEach { q -> indexed.decide(q); scan.decide(q) } } // прогрев JIT
        val t0 = System.nanoTime()
        queries.forEach(indexed::decide)
        val t1 = System.nanoTime()
        queries.forEach(scan::decide)
        val t2 = System.nanoTime()
        assertTrue((t1 - t0) * 10 < (t2 - t1), "индекс хотя бы в 10 раз быстрее перебора: ${(t1 - t0) / 1000} мкс против ${(t2 - t1) / 1000} мкс")
        assertEquals(RuleId("r4095"), indexed.decide(RouteQuery(domain = "a.site4095.example")).ruleId)
    }
}
