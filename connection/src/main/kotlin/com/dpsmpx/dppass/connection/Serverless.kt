package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.SplitSites

/**
 * Без сервера (D-73): выбор пользователя на этом телефоне, а не часть
 * документа (D-06) и не подписки (D-11). По умолчанию — остальные сайты
 * напрямую, DoH политики пользователя напрямую, приложения — как с сервером.
 */
data class ServerlessSettings(
    val rest: Rest = Rest.DIRECT,
    val dns: Dns = Dns.DOH,
    val apps: Apps = Apps.SAME,
    /** Свой выбор приложений ([Apps.OWN]): как в политике (D-38), но отдельно от неё. */
    val ownMode: AppMode = AppMode.ONLY,
    val ownApps: Set<String> = emptySet(),
) {
    /** Сайты не из списка D-72: напрямую, как без DPpass, или тоже с разбиением начала TLS. */
    enum class Rest(val wire: String) { DIRECT("direct"), SPLIT("split") }

    /** DoH сервера политики (D-38) напрямую или системный резолвер Android. */
    enum class Dns(val wire: String) { DOH("doh"), SYSTEM("system") }

    /** Какие приложения идут в туннель: как с сервером, свой выбор, все. */
    enum class Apps(val wire: String) { SAME("same"), OWN("own"), ALL("all") }

    companion object {
        val DEFAULT: ServerlessSettings = ServerlessSettings()

        /**
         * Значения из настроек телефона. Незнакомое значение (настройка
         * будущего выпуска, порча) — значение по умолчанию: это выбор на
         * телефоне, пользователь видит его в «Настройках» и меняет там.
         */
        fun of(rest: String?, dns: String?, apps: String?, ownMode: String?, ownApps: Set<String>): ServerlessSettings = ServerlessSettings(
            Rest.entries.firstOrNull { it.wire == rest } ?: DEFAULT.rest,
            Dns.entries.firstOrNull { it.wire == dns } ?: DEFAULT.dns,
            Apps.entries.firstOrNull { it.wire == apps } ?: DEFAULT.apps,
            AppMode.entries.firstOrNull { it.wire == ownMode } ?: DEFAULT.ownMode,
            ownApps,
        )
    }
}

/**
 * Режим без сервера (D-73): из выбора пользователя — конфигурация для TUN
 * и «Проверить маршрут» и план для ядра. Серверов в ней нет, правил
 * документа тоже: всё — напрямую; что идёт с разбиением, решает ядро по
 * плану ([ServerlessPlan]).
 */
object ServerlessMode {
    /** Единственный сервер DNS режима. */
    const val DNS_SERVER: String = "serverless"

    /** Есть ли туннелю что делать без сервера: сайты списка или разбиение всего. */
    fun useful(sites: SplitSites, s: ServerlessSettings): Boolean = !sites.isEmpty || s.rest == ServerlessSettings.Rest.SPLIT

    fun apps(s: ServerlessSettings, policy: UserPolicy): AppPolicy = when (s.apps) {
        ServerlessSettings.Apps.SAME -> PolicyBuilder.apps(policy.appMode, policy.apps)
        ServerlessSettings.Apps.OWN -> PolicyBuilder.apps(s.ownMode, s.ownApps)
        ServerlessSettings.Apps.ALL -> AppPolicy.AllApps
    }

    /**
     * DNS без сервера — только напрямую: через туннель его вести некуда.
     * Защиты от утечки нет по смыслу режима: имена спрашиваются мимо
     * туннеля, и это написано у выбора DNS.
     */
    fun dns(s: ServerlessSettings, policy: UserPolicy): DnsPolicy {
        val transport = when (s.dns) {
            ServerlessSettings.Dns.DOH -> DnsTransport.Https(policy.dns.url)
            ServerlessSettings.Dns.SYSTEM -> DnsTransport.System
        }
        return DnsPolicy(listOf(DnsServer(DNS_SERVER, transport, DnsRoute.DIRECT)), DNS_SERVER, leakProtection = false)
    }

    fun config(s: ServerlessSettings, policy: UserPolicy): ConfigIr = ConfigIr(
        name = null,
        profiles = emptyList(),
        routing = RoutingPolicy(defaultAction = RouteAction.DIRECT, apps = apps(s, policy), bypassLan = policy.bypassLan),
        dns = dns(s, policy),
    )

    fun plan(s: ServerlessSettings, sites: SplitSites, policy: UserPolicy): ServerlessPlan =
        ServerlessPlan(dns(s, policy), sites, splitRest = s.rest == ServerlessSettings.Rest.SPLIT)
}
