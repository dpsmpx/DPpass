package com.dpsmpx.dppass.routing

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.PortRange
import com.dpsmpx.dppass.core.RuleId

/**
 * Семантическая модель маршрутизации DPpass (D-09).
 *
 * Компактна намеренно: три действия и восемь видов условий. Её смысл
 * задаёт эталонный вычислитель [RouteEvaluator]; компиляторы под ядра
 * обязаны сохранить этот смысл или отказать с диагностикой — никогда
 * не «приблизить» молча.
 */
enum class RouteAction { DIRECT, PROXY, BLOCK }

enum class TransportProtocol { TCP, UDP }

/** Вид физической сети — условие правила («на мобильной — напрямую»). */
enum class NetworkKind { WIFI, MOBILE, ETHERNET, OTHER }

sealed interface DomainMatcher {
    /** Точное совпадение имени. */
    data class Full(val name: String) : DomainMatcher

    /** Имя совпадает с суффиксом или оканчивается на «.суффикс». */
    data class Suffix(val suffix: String) : DomainMatcher

    /** Имя содержит подстроку. */
    data class Keyword(val keyword: String) : DomainMatcher

    fun matches(domain: String): Boolean = when (this) {
        is Full -> domain == name
        // без конкатенации: на горячем пути объяснения решений это заметно
        is Suffix ->
            domain == suffix ||
                (domain.length > suffix.length && domain.endsWith(suffix) && domain[domain.length - suffix.length - 1] == '.')
        is Keyword -> keyword in domain
    }
}

/**
 * Условия правила. Непустые поля соединяются через И, значения внутри
 * поля — через ИЛИ: «(домен из списка ИЛИ IP из списка)» записывается
 * двумя правилами, а «домен из списка И порт 443» — одним.
 *
 * Пустое правило недопустимо: действие «для всего остального» — это
 * [RoutingPolicy.defaultAction].
 */
data class Conditions(
    val domains: List<DomainMatcher> = emptyList(),
    val ipCidrs: List<Cidr> = emptyList(),
    val geoSites: List<String> = emptyList(),
    val geoIps: List<String> = emptyList(),
    val apps: List<String> = emptyList(),
    val protocols: Set<TransportProtocol> = emptySet(),
    val ports: List<PortRange> = emptyList(),
    val networks: Set<NetworkKind> = emptySet(),
) {
    val isEmpty: Boolean
        get() = domains.isEmpty() && ipCidrs.isEmpty() && geoSites.isEmpty() && geoIps.isEmpty() &&
            apps.isEmpty() && protocols.isEmpty() && ports.isEmpty() && networks.isEmpty()

    /** Правило только про приложения: такое выражается на уровне VpnService. */
    val isAppsOnly: Boolean
        get() = apps.isNotEmpty() && copy(apps = emptyList()).isEmpty
}

data class Rule(val id: RuleId, val conditions: Conditions, val action: RouteAction)

/**
 * Какие приложения вообще идут в туннель — уровень VpnService, а не
 * правило внутри ядра. Собственный пакет DPpass в туннель не попадает
 * никогда (петля), это добавляет `tunnel/`, а не пользователь.
 */
sealed interface AppPolicy {
    data object AllApps : AppPolicy

    data class OnlyApps(val packages: Set<String>) : AppPolicy

    data class ExceptApps(val packages: Set<String>) : AppPolicy

    fun includes(packageName: String): Boolean = when (this) {
        AllApps -> true
        is OnlyApps -> packageName in packages
        is ExceptApps -> packageName !in packages
    }
}

/**
 * Когда у соединения есть только домен, а правило — про IP:
 * [NEVER] — IP-правила к нему не применяются; [IF_NO_DOMAIN_MATCH] —
 * если ни одно доменное правило не сработало, домен резолвится и
 * правила проверяются ещё раз по IP.
 */
enum class DomainResolution { NEVER, IF_NO_DOMAIN_MATCH }

data class RoutingPolicy(
    val rules: List<Rule> = emptyList(),
    val defaultAction: RouteAction = RouteAction.PROXY,
    val apps: AppPolicy = AppPolicy.AllApps,
    val domainResolution: DomainResolution = DomainResolution.NEVER,
    /** Локальные сети (RFC 1918, link-local, ULA) — мимо туннеля. */
    val bypassLan: Boolean = true,
    /**
     * Автоматический раздельный маршрут (D-45): после всех явных правил
     * отечественное назначение (`geosite:category-ru`, `geoip:ru`) идёт
     * `DIRECT`. По умолчанию выключено — документ пользователя значит
     * ровно то, что в нём написано (D-05); включает политика (режим
     * `AUTO`, D-38).
     */
    val automaticDomestic: Boolean = false,
)
