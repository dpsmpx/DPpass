package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsRule
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.Layers
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.SiteLists
import com.dpsmpx.dppass.subscriptions.Subscription

/**
 * Маршрутизация и DNS поставщика из подписки-документа DPpass, которые
 * пользователь привязал к подписке (D-98), — со своими настройками поверх.
 *
 * От поставщика — правила, действие по умолчанию, автосплит и DNS: на это
 * пользователь согласился. Свои — выбор приложений и локальная сеть мимо
 * туннеля (это про само устройство, поставщик его не знает) и свои списки
 * сайтов со списками поставщика из профиля маршрутизации (D-93, D-94):
 * их правила и имена — первыми, как и без привязки. Слой снимается по
 * началам id ([Layers]) и кладётся заново при смене настроек — правила
 * поставщика остаются как пришли; такие id у поставщика отвергает
 * конвейер подписки.
 */
object ProviderPolicy {
    fun routing(provider: RoutingPolicy, p: UserPolicy, lists: SiteLists): RoutingPolicy = provider.copy(
        rules = PolicyBuilder.ownRules(PolicyBuilder.own(p)) + PolicyBuilder.providerRules(lists) + provider.rules,
        apps = PolicyBuilder.apps(p.appMode, p.apps),
        bypassLan = p.bypassLan,
    )

    /**
     * Имена своих списков — своим серверам слоя: «через туннель» — копии
     * сервера по умолчанию поставщика, «напрямую» — системному резолверу
     * мимо туннеля (соединение с ними и так идёт мимо). Имён нет — DNS
     * поставщика как есть.
     */
    fun dns(provider: DnsPolicy, p: UserPolicy, lists: SiteLists): DnsPolicy {
        val layers = listOf(PolicyBuilder.own(p), lists).map { it.proxy.names() to it.direct.names() }
        val rules = layers.flatMap { (proxy, direct) ->
            listOfNotNull(
                proxy?.let { DnsRule(it.domains, it.geoSites, Layers.DNS_REMOTE) },
                direct?.let { DnsRule(it.domains, it.geoSites, Layers.DNS_LOCAL) },
            )
        }
        if (rules.isEmpty()) return provider
        val used = rules.map { it.serverId }.toSet()
        val remote = provider.servers.first { it.id == provider.defaultServerId }.copy(id = Layers.DNS_REMOTE)
        val local = DnsServer(Layers.DNS_LOCAL, DnsTransport.System, DnsRoute.DIRECT)
        return provider.copy(
            servers = provider.servers + listOf(remote, local).filter { it.id in used },
            rules = rules + provider.rules,
        )
    }

    /**
     * Выбор приложений и локальная сеть поставщика, которые не взяты
     * (D-98): не молча (D-05) — находка с причиной.
     */
    fun notTaken(provider: RoutingPolicy?, p: UserPolicy): Diagnostic? {
        if (provider == null) return null
        val apps = provider.apps != PolicyBuilder.apps(p.appMode, p.apps)
        val lan = provider.bypassLan != p.bypassLan
        if (!apps && !lan) return null
        val what = listOfNotNull("выбор приложений".takeIf { apps }, "локальная сеть мимо туннеля".takeIf { lan }).joinToString(" и ")
        return Diagnostic.warning(
            DiagCode.SUBSCRIPTION_DIRECTIVE_IGNORED,
            "маршрутизация поставщика: $what — ваши, значения из подписки не взяты",
            "$.routing",
        )
    }

    /** Правила поставщика без слоя своих настроек. */
    fun strip(routing: RoutingPolicy): RoutingPolicy = routing.copy(rules = routing.rules.filterNot { Layers.isLayerRule(it.id) })

    /** DNS поставщика без серверов и правил слоя. */
    fun strip(dns: DnsPolicy): DnsPolicy = dns.copy(
        servers = dns.servers.filterNot { Layers.isLayerServer(it.id) },
        rules = dns.rules.filterNot { Layers.isLayerServer(it.serverId) },
    )

    /** Конфигурация привязанной подписки — с новыми своими настройками поверх тех же правил поставщика. */
    fun relayer(config: ConfigIr, p: UserPolicy, lists: SiteLists): ConfigIr =
        config.copy(routing = routing(strip(config.routing), p, lists), dns = dns(strip(config.dns), p, lists))
}

/**
 * Действуют ли сейчас маршрутизация и DNS поставщика (D-98): применена
 * подписка, привязанная к ним, и её последняя принятая ревизия — документ
 * DPpass. Для окна у подписки и пометки в настройках маршрутизации.
 */
data class ProviderPolicyState(val subscription: Subscription)

/** Маршрутизация и DNS поставщика у подписки (D-98) — строка окна у подписки на телефоне и ПК. */
enum class ProviderPolicyStatus {
    /** Не привязаны: действуют свои. */
    OFF,

    /** Привязаны и действуют. */
    IN_USE,

    /** Привязаны, но подписка не применена: подействуют, когда её применят. */
    NOT_APPLIED,

    /** Привязаны, но последняя принятая ревизия — не документ DPpass: действуют свои. */
    NOT_OFFERED,
}
