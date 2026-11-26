package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RoutingPolicy

/** D-120: гостевой VPN использует только выбранный профиль, без правил direct с телефона. */
internal object RootHotspotVpnPlan {
    /** Для одноразового стенда: не выбираем сервер произвольно из нескольких. */
    fun decodeSingle(body: ByteArray): ServerProfile {
        val decoded = com.dpsmpx.dppass.subscriptions.PayloadDecoder.decode(body, "guest", 128)
        check(decoded is com.dpsmpx.dppass.diagnostics.Outcome.Success) { "Неподдерживаемый формат профиля" }
        return decoded.value.profiles.single().also { profile ->
            require(!isLocalPlaceholder(profile.endpoint.host)) { "В подписке нет удалённой точки входа" }
        }
    }

    /** Проверка буквального адреса без DNS; частный адрес сам по себе допустим. */
    internal fun isLocalPlaceholder(host: com.dpsmpx.dppass.core.Host): Boolean = when (host) {
        is com.dpsmpx.dppass.core.Host.Domain -> host.name == "localhost" || host.name.endsWith(".localhost")
        is com.dpsmpx.dppass.core.Host.Ip -> java.net.InetAddress.getByAddress(host.address.toBytes()).let {
            it.isLoopbackAddress || it.isAnyLocalAddress
        }
    }

    fun compile(profile: ServerProfile) = XrayCompiler(dnsHijackAnyAddress = true).compile(
        ConfigIr(
            name = null,
            profiles = listOf(profile),
            routing = RoutingPolicy(defaultAction = RouteAction.PROXY, bypassLan = false),
            dns = DnsPolicy(
                servers = listOf(DnsServer("guest-doh", DnsTransport.Https("https://1.1.1.1/dns-query"), DnsRoute.TUNNEL)),
                defaultServerId = "guest-doh",
            ),
        ),
        CompilePlan(profileId = profile.id, withTun = true),
    )
}
