package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.Rule

/**
 * IR → документ формата текущей версии.
 *
 * [Mode.REDACTED] — по умолчанию для экспорта (D-11): секреты заменены
 * меткой, такой документ можно показать, но не активировать (проверка
 * отвергнет метку). [Mode.FULL] — только для собственного хранилища и
 * явного «экспорт с секретами».
 */
object ConfigWriter {
    enum class Mode { REDACTED, FULL }

    fun write(ir: ConfigIr, mode: Mode = Mode.REDACTED): String = Json.write(toJson(ir, mode))

    fun toJson(ir: ConfigIr, mode: Mode): JsonObject {
        fun secret(s: Secret?): JsonValue? = s?.let { Json.str(if (mode == Mode.FULL) it.reveal() else Secret.REDACTED) }

        val profiles = ir.profiles.map { p ->
            val protocol = when (val pr = p.protocol) {
                is ProtocolSpec.Vless -> Json.obj("type" to Json.str("vless"), "id" to secret(pr.id), "flow" to Json.str(pr.flow.wire))
                is ProtocolSpec.Trojan -> Json.obj("type" to Json.str("trojan"), "password" to secret(pr.password))
                is ProtocolSpec.Shadowsocks -> Json.obj(
                    "type" to Json.str("shadowsocks"),
                    "method" to Json.str(pr.method.wire),
                    "password" to secret(pr.password),
                )
                is ProtocolSpec.Hysteria2 -> Json.obj(
                    "type" to Json.str("hysteria2"),
                    "password" to secret(pr.password),
                    "obfs_password" to secret(pr.obfsPassword),
                    "congestion" to Json.str(pr.congestion?.wire),
                )
                // Устройство раздачи (D-55) живёт только в списке устройств, в IR активации
                // его не бывает; в формате документа такого протокола нет.
                is ProtocolSpec.Socks -> throw IllegalArgumentException("устройство раздачи не записывается в документ (D-55)")
            }
            val transport = when (val t = p.transport) {
                TransportSpec.Tcp -> Json.obj("type" to Json.str("tcp"))
                TransportSpec.Native -> Json.obj("type" to Json.str("native"))
                is TransportSpec.WebSocket -> Json.obj("type" to Json.str("websocket"), "path" to Json.str(t.path), "host" to Json.str(t.host))
                is TransportSpec.HttpUpgrade -> Json.obj("type" to Json.str("httpupgrade"), "path" to Json.str(t.path), "host" to Json.str(t.host))
                is TransportSpec.Grpc -> Json.obj("type" to Json.str("grpc"), "service_name" to Json.str(t.serviceName))
                is TransportSpec.XHttp -> JsonObject(
                    Json.obj(
                        "type" to Json.str("xhttp"),
                        "path" to Json.str(t.path),
                        "host" to Json.str(t.host),
                        "mode" to Json.str(t.mode.wire),
                    ).fields + xhttpExtra(t.extra).fields,
                )
            }
            val security = when (val s = p.security) {
                SecuritySpec.None -> Json.obj("type" to Json.str("none"))
                is SecuritySpec.Tls -> Json.obj(
                    "type" to Json.str("tls"),
                    "server_name" to Json.str(s.serverName),
                    "alpn" to s.alpn.takeIf { it.isNotEmpty() }?.let(Json::strings),
                    "fingerprint" to Json.str(s.fingerprint?.wire),
                )
                is SecuritySpec.Reality -> Json.obj(
                    "type" to Json.str("reality"),
                    "server_name" to Json.str(s.serverName),
                    "public_key" to Json.str(s.publicKey),
                    "short_id" to secret(s.shortId),
                    "fingerprint" to Json.str(s.fingerprint.wire),
                    "spider_x" to Json.str(s.spiderX),
                )
            }
            Json.obj(
                "id" to Json.str(p.id.value),
                "name" to Json.str(p.name),
                "server" to Json.str(p.endpoint.host.toString()),
                "port" to Json.num(p.endpoint.port),
                "protocol" to protocol,
                "transport" to transport,
                "security" to security,
                "hints" to Json.obj(
                    "priority" to Json.num(p.hints.priority),
                    "allowlist_reachable" to Json.bool(p.hints.reachableUnderAllowlist),
                ),
            )
        }
        val r = ir.routing
        val apps = when (val a = r.apps) {
            AppPolicy.AllApps -> Json.obj("mode" to Json.str("all"))
            is AppPolicy.OnlyApps -> Json.obj("mode" to Json.str("only"), "packages" to Json.strings(a.packages.sorted()))
            is AppPolicy.ExceptApps -> Json.obj("mode" to Json.str("except"), "packages" to Json.strings(a.packages.sorted()))
        }
        val routing = Json.obj(
            "default" to Json.str(r.defaultAction.name.lowercase()),
            "domain_resolution" to Json.str(r.domainResolution.name.lowercase()),
            "bypass_lan" to Json.bool(r.bypassLan),
            "automatic_domestic" to Json.bool(r.automaticDomestic),
            "apps" to apps,
            "rules" to Json.arr(r.rules.map(::rule)),
        )
        val d = ir.dns
        val dns = Json.obj(
            "servers" to Json.arr(
                d.servers.map { s ->
                    val route = Json.str(if (s.route == DnsRoute.TUNNEL) "tunnel" else "direct")
                    when (val t = s.transport) {
                        is DnsTransport.Udp -> Json.obj("id" to Json.str(s.id), "type" to Json.str("udp"), "address" to Json.str(t.server.toString()), "route" to route)
                        is DnsTransport.Tcp -> Json.obj("id" to Json.str(s.id), "type" to Json.str("tcp"), "address" to Json.str(t.server.toString()), "route" to route)
                        is DnsTransport.Https -> Json.obj("id" to Json.str(s.id), "type" to Json.str("https"), "url" to Json.str(t.url), "route" to route)
                        is DnsTransport.Tls -> Json.obj(
                            "id" to Json.str(s.id),
                            "type" to Json.str("tls"),
                            "address" to Json.str(t.server.toString()),
                            "server_name" to Json.str(t.serverName),
                            "route" to route,
                        )
                        DnsTransport.System -> Json.obj("id" to Json.str(s.id), "type" to Json.str("system"), "route" to route)
                    }
                },
            ),
            "default" to Json.str(d.defaultServerId),
            "rules" to Json.arr(
                d.rules.map { dr ->
                    Json.obj(
                        "domain" to domains<DomainMatcher.Full>(dr.domains) { it.name },
                        "domain_suffix" to domains<DomainMatcher.Suffix>(dr.domains) { it.suffix },
                        "geosite" to dr.geoSites.takeIf { it.isNotEmpty() }?.let(Json::strings),
                        "server" to Json.str(dr.serverId),
                    )
                },
            ),
            "strategy" to Json.str(d.strategy.name.lowercase()),
            "leak_protection" to Json.bool(d.leakProtection),
        )
        return Json.obj(
            "format" to Json.str(ConfigFormat.MARKER),
            "format_version" to Json.num(ConfigFormat.CURRENT_VERSION),
            "name" to Json.str(ir.name),
            "profiles" to Json.arr(profiles),
            "routing" to routing,
            "dns" to dns,
        )
    }

    /** Настройки XHTTP формата 2 (D-37): только заданные — значения по умолчанию ядра не пишутся. */
    private fun xhttpExtra(e: XHttpExtra): JsonObject {
        fun range(r: CountRange?): JsonValue? = r?.let { if (it.from == it.to) Json.num(it.from) else Json.str(it.toString()) }
        return Json.obj(
            "x_padding_bytes" to range(e.xPaddingBytes),
            "sc_max_each_post_bytes" to range(e.scMaxEachPostBytes),
            "sc_min_posts_interval_ms" to range(e.scMinPostsIntervalMs),
            "no_grpc_header" to Json.bool(true).takeIf { e.noGrpcHeader },
            "xmux" to e.xmux?.let { x ->
                Json.obj(
                    "max_concurrency" to range(x.maxConcurrency),
                    "max_connections" to range(x.maxConnections),
                    "c_max_reuse_times" to range(x.cMaxReuseTimes),
                    "h_max_request_times" to range(x.hMaxRequestTimes),
                    "h_max_reusable_secs" to range(x.hMaxReusableSecs),
                    "h_keep_alive_period" to x.hKeepAlivePeriod?.let(Json::num),
                )
            },
        )
    }

    private fun rule(rule: Rule): JsonObject {
        val c = rule.conditions
        fun list(items: List<String>) = items.takeIf { it.isNotEmpty() }?.let(Json::strings)
        return Json.obj(
            "id" to Json.str(rule.id.value),
            "action" to Json.str(rule.action.name.lowercase()),
            "domain" to domains<DomainMatcher.Full>(c.domains) { it.name },
            "domain_suffix" to domains<DomainMatcher.Suffix>(c.domains) { it.suffix },
            "domain_keyword" to domains<DomainMatcher.Keyword>(c.domains) { it.keyword },
            "ip_cidr" to list(c.ipCidrs.map { it.toString() }),
            "geosite" to list(c.geoSites),
            "geoip" to list(c.geoIps),
            "apps" to list(c.apps),
            "protocol" to list(c.protocols.map { it.name.lowercase() }.sorted()),
            "port" to list(c.ports.map { it.toString() }),
            "network" to list(c.networks.map { it.name.lowercase() }.sorted()),
        )
    }

    private inline fun <reified T : DomainMatcher> domains(all: List<DomainMatcher>, value: (T) -> String): JsonValue? =
        all.filterIsInstance<T>().map(value).takeIf { it.isNotEmpty() }?.let(Json::strings)
}
