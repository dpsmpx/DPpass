package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.RuleId

/**
 * Геоданные для вычислителя. Реальный источник (geosite/geoip ядра)
 * подключается вместе с ядром; в тестах — таблица.
 */
interface GeoResolver {
    fun siteMatches(code: String, domain: String): Boolean
    fun ipMatches(code: String, ip: IpAddress): Boolean

    /** Пустая база: ни одно гео-условие не выполняется. */
    object None : GeoResolver {
        override fun siteMatches(code: String, domain: String): Boolean = false
        override fun ipMatches(code: String, ip: IpAddress): Boolean = false
    }
}

class TableGeoResolver(
    private val sites: Map<String, List<DomainMatcher>> = emptyMap(),
    private val ips: Map<String, List<Cidr>> = emptyMap(),
) : GeoResolver {
    override fun siteMatches(code: String, domain: String): Boolean = sites[code].orEmpty().any { it.matches(domain) }
    override fun ipMatches(code: String, ip: IpAddress): Boolean = ips[code].orEmpty().any { ip in it }
}

/** Что известно о соединении в момент решения. */
data class RouteQuery(
    val domain: String? = null,
    val ip: IpAddress? = null,
    val port: Int? = null,
    val protocol: TransportProtocol? = null,
    val packageName: String? = null,
    val network: NetworkKind? = null,
    /** Адрес, в который резолвится [domain] (для [DomainResolution.IF_NO_DOMAIN_MATCH]). */
    val resolvedIp: IpAddress? = null,
)

data class RouteDecision(val action: RouteAction, val ruleId: RuleId?, val reason: String)

/**
 * Эталонный смысл маршрутизации: первое сработавшее правило по порядку;
 * иначе — действие по умолчанию. Приложение вне туннеля — DIRECT до
 * всяких правил.
 *
 * Используется для объяснения решений пользователю, проверки
 * компиляторов (одинаковые ответы на корпусе запросов) и тестов. Сам
 * трафик маршрутизирует ядро.
 *
 * Правила-кандидаты — по индексу имён ([RuleIndex], D-89): правило с
 * доменами только точными и суффиксами проверяется, лишь если имя
 * запроса или один из его суффиксов есть в индексе. Порядок — прежний,
 * смысл — тот же, что у перебора всех правил ([indexed] = false —
 * перебор, эталон для тестов индекса).
 */
class RouteEvaluator(
    private val policy: RoutingPolicy,
    private val geo: GeoResolver = GeoResolver.None,
    private val indexed: Boolean = true,
) {
    private val index: RuleIndex? = if (indexed) RuleIndex(policy.rules) else null

    fun decide(query: RouteQuery): RouteDecision {
        val pkg = query.packageName
        if (pkg != null && !policy.apps.includes(pkg)) {
            return RouteDecision(RouteAction.DIRECT, null, "приложение $pkg вне туннеля (политика приложений)")
        }
        firstMatch(query)?.let { return it }
        if (policy.domainResolution == DomainResolution.IF_NO_DOMAIN_MATCH && query.ip == null && query.resolvedIp != null) {
            firstMatch(query.copy(ip = query.resolvedIp))?.let {
                return it.copy(reason = it.reason + " (по IP после резолва домена)")
            }
        }
        // Автоматический раздельный маршрут (D-45): после явных правил
        // отечественное назначение — напрямую. Явные правила выше по порядку,
        // поэтому смысл документа не меняется (D-05).
        if (policy.automaticDomestic) {
            val domestic = query.domain?.let { geo.siteMatches(SITE_RU, it) } == true ||
                (query.ip ?: query.resolvedIp)?.let { geo.ipMatches(IP_RU, it) } == true
            if (domestic) return RouteDecision(RouteAction.DIRECT, null, "автоматический раздельный маршрут: отечественное напрямую (geosite/geoip:ru)")
        }
        return RouteDecision(policy.defaultAction, null, "ни одно правило не сработало — действие по умолчанию")
    }

    private fun firstMatch(query: RouteQuery): RouteDecision? {
        val rules = policy.rules
        val candidates = index?.candidates(query.domain)
        if (candidates == null) {
            for (rule in rules) {
                if (matches(rule.conditions, query)) return RouteDecision(rule.action, rule.id, "правило ${rule.id}")
            }
            return null
        }
        for (i in candidates) {
            val rule = rules[i]
            if (matches(rule.conditions, query)) return RouteDecision(rule.action, rule.id, "правило ${rule.id}")
        }
        return null
    }

    private fun matches(c: Conditions, q: RouteQuery): Boolean {
        if (c.isEmpty) return false
        if (c.domains.isNotEmpty() || c.geoSites.isNotEmpty()) {
            val d = q.domain ?: return false
            val byDomain = c.domains.any { it.matches(d) }
            val byGeo = c.geoSites.any { geo.siteMatches(it, d) }
            // домены и geosite — одно поле «назначение по имени»: ИЛИ между ними
            if (!byDomain && !byGeo) return false
        }
        if (c.ipCidrs.isNotEmpty() || c.geoIps.isNotEmpty()) {
            val ip = q.ip ?: return false
            val byCidr = c.ipCidrs.any { ip in it }
            val byGeo = c.geoIps.any { geo.ipMatches(it, ip) }
            if (!byCidr && !byGeo) return false
        }
        if (c.apps.isNotEmpty() && (q.packageName == null || q.packageName !in c.apps)) return false
        if (c.protocols.isNotEmpty() && (q.protocol == null || q.protocol !in c.protocols)) return false
        if (c.ports.isNotEmpty() && (q.port == null || c.ports.none { q.port in it })) return false
        if (c.networks.isNotEmpty() && (q.network == null || q.network !in c.networks)) return false
        return true
    }

    companion object {
        /** Коды набора геоданных (D-27) для автосплита (D-45); те же, что в PolicyBuilder. */
        const val SITE_RU: String = "category-ru"
        const val IP_RU: String = "ru"
    }
}
