package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.PortRange
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.DiagnosticCollector
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.Conditions
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsRule
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsStrategy
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.DomainResolution
import com.dpsmpx.dppass.routing.NetworkKind
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.RoutingValidator
import com.dpsmpx.dppass.routing.Rule
import com.dpsmpx.dppass.routing.TransportProtocol

/**
 * Документ текущего формата (2, D-37; версию 1 до него доводит миграция) → IR.
 * Значения нормализуются при чтении (домены в
 * нижнем регистре, подсети канонически) с пометкой там, где запись
 * отличалась; всё, что не укладывается в IR, — ошибка с путём.
 */
internal class DocumentMapper(private val diags: DiagnosticCollector, private val limits: ConfigLimits) {

    fun map(root: JsonObject): ConfigIr? {
        val r = ObjReader(root, "$", diags)
        r.string("format")
        r.int("format_version")
        val name = r.string("name", required = false)?.let { checkName(it, "$.name") }
        val profiles = r.objects("profiles").mapNotNull(::profile)
        val routing = r.obj("routing", required = false)?.let(::routing) ?: RoutingPolicy()
        val dns = r.obj("dns")?.let(::dns)
        r.finish()
        if (dns == null) return null
        return ConfigIr(name, profiles, routing, dns)
    }

    // ---- профили ----

    private fun profile(r: ObjReader): ServerProfile? {
        val id = r.string("id")?.let { checkId(it, "${r.path}.id") }
        val name = r.string("name")?.let { checkName(it, "${r.path}.name") }
        val server = r.string("server")?.let { s ->
            Host.parse(s) ?: run {
                diags.error(DiagCode.HOST_INVALID, "адрес сервера — не домен и не IP", "${r.path}.server")
                null
            }
        }
        val port = r.int("port", range = 1..65535)
        val protocol = r.obj("protocol")?.let(::protocol)
        val transport = r.obj("transport", required = false)?.let(::transport) ?: TransportSpec.Tcp
        val security = r.obj("security")?.let(::security)
        val hints = r.obj("hints", required = false)?.let { h ->
            val p = h.int("priority", required = false, range = -1000..1000) ?: 0
            val a = h.bool("allowlist_reachable", false)
            h.finish()
            CandidateHints(p, a)
        } ?: CandidateHints()
        r.finish()
        if (id == null || name == null || server == null || port == null || protocol == null || security == null) return null
        return ServerProfile(ProfileId(id), name, Endpoint(server, port), protocol, transport, security, hints)
    }

    private fun protocol(r: ObjReader): ProtocolSpec? {
        val type = r.enum("type", PROTOCOLS) ?: return null.also { r.finish() }
        val spec = when (type) {
            ProtocolKind.VLESS -> {
                val id = r.secret("id")
                val flow = r.enum("flow", FLOWS, required = false, default = VlessFlow.NONE)
                if (id == null || flow == null) null else ProtocolSpec.Vless(id, flow)
            }
            ProtocolKind.TROJAN -> r.secret("password")?.let(ProtocolSpec::Trojan)
            ProtocolKind.SHADOWSOCKS -> {
                val method = r.enum("method", SS_METHODS)
                val password = r.secret("password")
                if (method == null || password == null) null else ProtocolSpec.Shadowsocks(method, password)
            }
            ProtocolKind.HYSTERIA2 -> {
                val password = r.secret("password")
                val obfs = r.secret("obfs_password", required = false)
                val congestion = r.enum("congestion", CONGESTIONS, required = false)
                val quic = r.obj("quic", required = false)?.let(::quic)
                val hop = r.obj("hop", required = false)?.let(::hop)
                password?.let { ProtocolSpec.Hysteria2(it, obfs, congestion, quic?.takeUnless { q -> q.isEmpty }, hop) }
            }
            // В PROTOCOLS его нет: устройство раздачи в документе не бывает (D-55).
            ProtocolKind.SOCKS -> null
        }
        r.finish()
        return spec
    }

    private fun transport(r: ObjReader): TransportSpec? {
        val type = r.enum("type", TRANSPORTS) ?: return null.also { r.finish() }
        val spec = when (type) {
            TransportKind.TCP -> TransportSpec.Tcp
            TransportKind.NATIVE -> TransportSpec.Native
            TransportKind.WEBSOCKET -> path(r)?.let { TransportSpec.WebSocket(it, hostHeader(r)) }
            TransportKind.HTTPUPGRADE -> path(r)?.let { TransportSpec.HttpUpgrade(it, hostHeader(r)) }
            TransportKind.XHTTP -> {
                val p = path(r)
                val h = hostHeader(r)
                val mode = r.enum("mode", XHTTP_MODES, required = false, default = XHttpMode.AUTO)
                val extra = xhttpExtra(r)
                if (p == null || mode == null) null else TransportSpec.XHttp(p, h, mode, extra)
            }
            TransportKind.GRPC -> r.string("service_name")?.let { s ->
                if (!ConfigValidator.isValidServiceName(s)) {
                    diags.error(DiagCode.PATH_INVALID, ConfigValidator.SERVICE_NAME_MESSAGE, "${r.path}.service_name")
                    null
                } else {
                    TransportSpec.Grpc(s)
                }
            }
        }
        r.finish()
        return spec
    }

    /** Параметры QUIC Hysteria2 (формат 3, D-107); пределы значений — `ConfigValidator`. */
    private fun quic(r: ObjReader): Hysteria2Quic {
        fun long(key: String): Long? = r.long(key, required = false, range = 0..Long.MAX_VALUE)?.takeIf { it > 0 }
        val q = Hysteria2Quic(
            bbrProfile = r.enum("bbr_profile", BBR_PROFILES, required = false),
            brutalUp = long("brutal_up"),
            brutalDown = long("brutal_down"),
            brutalDisableLossCompensation = r.bool("brutal_disable_loss_compensation", false),
            initStreamReceiveWindow = long("init_stream_receive_window"),
            maxStreamReceiveWindow = long("max_stream_receive_window"),
            initConnReceiveWindow = long("init_connection_receive_window"),
            maxConnReceiveWindow = long("max_connection_receive_window"),
            maxIdleTimeoutSecs = r.int("max_idle_timeout", required = false, range = 0..Int.MAX_VALUE)?.takeIf { it > 0 },
            keepAlivePeriodSecs = r.int("keep_alive_period", required = false, range = 0..Int.MAX_VALUE)?.takeIf { it > 0 },
            disablePathMtuDiscovery = r.bool("disable_path_mtu_discovery", false),
            disableChromeParrot = r.bool("disable_chrome_parrot", false),
            disableGso = r.bool("disable_gso", false),
        )
        r.finish()
        return q
    }

    /** Перескок портов Hysteria2 (формат 3, D-107). */
    private fun hop(r: ObjReader): Hysteria2Hop? {
        val modes = r.strings("modes", required = true).mapNotNull { (v, at) ->
            HOP_MODES[v] ?: null.also { diags.error(DiagCode.VALUE_UNKNOWN, "неизвестный режим перескока; допустимо: ${HOP_MODES.keys.joinToString()}", at) }
        }
        val ports = r.strings("ports", required = true).mapNotNull { (v, at) ->
            PortRange.parse(v) ?: null.also { diags.error(DiagCode.TRANSPORT_SETTING_INVALID, "порт или диапазон портов «N» или «N-M», 1…65535", at) }
        }
        val interval = r.range("interval")
        r.finish()
        if (modes.isEmpty() || ports.isEmpty()) return null
        return Hysteria2Hop(modes.toSet(), ports, interval)
    }

    /** Настройки XHTTP формата 2 (D-37) — поля того же объекта `transport`. */
    private fun xhttpExtra(r: ObjReader): XHttpExtra {
        val xmux = r.obj("xmux", required = false)?.let { x ->
            val m = Xmux(
                maxConcurrency = x.range("max_concurrency"),
                maxConnections = x.range("max_connections"),
                cMaxReuseTimes = x.range("c_max_reuse_times"),
                hMaxRequestTimes = x.range("h_max_request_times"),
                hMaxReusableSecs = x.range("h_max_reusable_secs"),
                hKeepAlivePeriod = x.int("h_keep_alive_period", required = false, range = -1..86_400)?.takeIf { it != 0 },
            )
            x.finish()
            m.takeUnless { it.isEmpty }
        }
        return XHttpExtra(
            xPaddingBytes = r.range("x_padding_bytes"),
            scMaxEachPostBytes = r.range("sc_max_each_post_bytes"),
            scMinPostsIntervalMs = r.range("sc_min_posts_interval_ms"),
            noGrpcHeader = r.bool("no_grpc_header", false),
            xmux = xmux,
        )
    }

    private fun path(r: ObjReader): String? = r.string("path")?.let { p ->
        if (!ConfigValidator.isValidPath(p)) {
            diags.error(DiagCode.PATH_INVALID, ConfigValidator.PATH_MESSAGE, "${r.path}.path")
            null
        } else {
            p
        }
    }

    private fun hostHeader(r: ObjReader): String? = r.string("host", required = false)?.let { h ->
        Host.normalizeDomain(h) ?: run {
            diags.error(DiagCode.DOMAIN_INVALID, "host — не домен", "${r.path}.host")
            null
        }
    }

    private fun security(r: ObjReader): SecuritySpec? {
        val type = r.enum("type", SECURITIES) ?: return null.also { r.finish() }
        val spec = when (type) {
            SecurityKind.NONE -> SecuritySpec.None
            SecurityKind.TLS -> {
                val sni = r.string("server_name", required = false)?.let { serverName(it, "${r.path}.server_name") }
                val alpn = r.strings("alpn").map { it.first }
                val fp = r.enum("fingerprint", FINGERPRINTS, required = false)
                if (r.bool("allow_insecure", false)) {
                    diags.error(
                        DiagCode.INSECURE_TLS_REJECTED,
                        "отключение проверки сертификата не поддерживается: соединение было бы открыто для подмены",
                        "${r.path}.allow_insecure",
                    )
                }
                SecuritySpec.Tls(sni, alpn, fp)
            }
            SecurityKind.REALITY -> {
                val sni = r.string("server_name")?.let { serverName(it, "${r.path}.server_name") }
                val key = r.string("public_key")
                val shortId = r.secret("short_id")
                val fp = r.enum("fingerprint", FINGERPRINTS, required = false, default = TlsFingerprint.CHROME)
                val spider = r.string("spider_x", required = false)
                if (sni == null || key == null || shortId == null || fp == null) null else SecuritySpec.Reality(sni, key, shortId, fp, spider)
            }
        }
        r.finish()
        return spec
    }

    private fun serverName(s: String, path: String): String? = Host.normalizeDomain(s) ?: run {
        diags.error(DiagCode.SERVER_NAME_INVALID, "server_name должно быть доменным именем", path)
        null
    }

    // ---- маршрутизация ----

    private fun routing(r: ObjReader): RoutingPolicy {
        val default = r.enum("default", ACTIONS, required = false, default = RouteAction.PROXY) ?: RouteAction.PROXY
        val resolution = r.enum("domain_resolution", RESOLUTIONS, required = false, default = DomainResolution.NEVER)
            ?: DomainResolution.NEVER
        val bypassLan = r.bool("bypass_lan", true)
        // Автосплит (D-45): по умолчанию false — документ значит ровно то, что в нём (D-05).
        val automaticDomestic = r.bool("automatic_domestic", false)
        val apps = r.obj("apps", required = false)?.let(::apps) ?: AppPolicy.AllApps
        val rules = r.objects("rules", required = false).mapNotNull(::rule)
        r.finish()
        return RoutingPolicy(rules, default, apps, resolution, bypassLan, automaticDomestic)
    }

    private fun apps(r: ObjReader): AppPolicy? {
        val mode = r.enum("mode", mapOf("all" to 0, "only" to 1, "except" to 2))
        val packages = packages(r.strings("packages"))
        r.finish()
        return when (mode) {
            0 -> AppPolicy.AllApps
            1 -> AppPolicy.OnlyApps(packages.toSet())
            2 -> AppPolicy.ExceptApps(packages.toSet())
            else -> null
        }
    }

    private fun rule(r: ObjReader): Rule? {
        val id = r.string("id")?.let { checkId(it, "${r.path}.id") }
        val action = r.enum("action", ACTIONS)
        val domains = r.strings("domain").mapNotNull { (v, p) -> domain(v, p)?.let(DomainMatcher::Full) } +
            r.strings("domain_suffix").mapNotNull { (v, p) -> domain(v, p)?.let(DomainMatcher::Suffix) } +
            r.strings("domain_keyword").mapNotNull { (v, p) -> keyword(v, p)?.let(DomainMatcher::Keyword) }
        val conditions = Conditions(
            domains = domains,
            ipCidrs = r.strings("ip_cidr").mapNotNull { (v, p) -> cidr(v, p) },
            geoSites = r.strings("geosite").mapNotNull { (v, p) -> geo(v, p) },
            geoIps = r.strings("geoip").mapNotNull { (v, p) -> geo(v, p) },
            apps = packages(r.strings("apps")),
            protocols = r.strings("protocol").mapNotNull { (v, p) -> named(v, p, PROTOCOLS_NET) }.toSet(),
            ports = r.strings("port").mapNotNull { (v, p) ->
                PortRange.parse(v) ?: run {
                    diags.error(DiagCode.PORT_RANGE_INVALID, "порт или диапазон «a-b» в 1..65535", p)
                    null
                }
            },
            networks = r.strings("network").mapNotNull { (v, p) -> named(v, p, NETWORKS) }.toSet(),
        )
        r.finish()
        if (id == null || action == null) return null
        return Rule(RuleId(id), conditions, action)
    }

    // ---- DNS ----

    private fun dns(r: ObjReader): DnsPolicy? {
        val servers = r.objects("servers").mapNotNull(::dnsServer)
        val default = r.string("default")
        val rules = r.objects("rules", required = false).mapNotNull { dr ->
            val ds = dr.strings("domain").mapNotNull { (v, p) -> domain(v, p)?.let(DomainMatcher::Full) } +
                dr.strings("domain_suffix").mapNotNull { (v, p) -> domain(v, p)?.let(DomainMatcher::Suffix) }
            val geo = dr.strings("geosite").mapNotNull { (v, p) -> geo(v, p) }
            val server = dr.string("server")
            dr.finish()
            server?.let { DnsRule(ds, geo, it) }
        }
        val strategy = r.enum("strategy", STRATEGIES, required = false, default = DnsStrategy.PREFER_IPV4)
        val leak = r.bool("leak_protection", true)
        r.finish()
        if (default == null || strategy == null) return null
        return DnsPolicy(servers, default, rules, strategy, leak)
    }

    private fun dnsServer(r: ObjReader): DnsServer? {
        val id = r.string("id")?.let { checkId(it, "${r.path}.id") }
        val type = r.enum("type", mapOf("udp" to 0, "tcp" to 1, "https" to 2, "tls" to 3, "system" to 4))
        val route = r.enum("route", mapOf("tunnel" to DnsRoute.TUNNEL, "direct" to DnsRoute.DIRECT))
        val transport: DnsTransport? = when (type) {
            0 -> r.string("address")?.let { hostPort(it, 53, "${r.path}.address") }?.let(DnsTransport::Udp)
            1 -> r.string("address")?.let { hostPort(it, 53, "${r.path}.address") }?.let(DnsTransport::Tcp)
            2 -> r.string("url")?.let { u ->
                if (u.startsWith("https://") && u.length <= 2048 && u.none { it.isWhitespace() }) {
                    DnsTransport.Https(u)
                } else {
                    diags.error(DiagCode.DNS_SERVER_INVALID, "url DoH должен начинаться с https://", "${r.path}.url")
                    null
                }
            }
            3 -> {
                val ep = r.string("address")?.let { hostPort(it, 853, "${r.path}.address") }
                val sni = r.string("server_name", required = false)?.let { serverName(it, "${r.path}.server_name") }
                ep?.let { DnsTransport.Tls(it, sni) }
            }
            4 -> DnsTransport.System
            else -> null
        }
        r.finish()
        if (id == null || transport == null || route == null) return null
        return DnsServer(id, transport, route)
    }

    private fun hostPort(text: String, defaultPort: Int, path: String): Endpoint? {
        val (hostText, portText) = when {
            text.startsWith("[") -> {
                val end = text.indexOf(']')
                if (end < 0) null to null else text.substring(0, end + 1) to text.substring(end + 1).removePrefix(":").ifEmpty { null }
            }
            text.count { it == ':' } == 1 -> text.substringBefore(':') to text.substringAfter(':')
            else -> text to null
        }
        val host = hostText?.let(Host::parse)
        val port = if (portText == null) defaultPort else portText.toIntOrNull()
        if (host == null || port == null || port !in 1..65535) {
            diags.error(DiagCode.DNS_SERVER_INVALID, "адрес должен быть «хост[:порт]»", path)
            return null
        }
        return Endpoint(host, port)
    }

    // ---- значения ----

    private fun checkId(id: String, path: String): String? = if (Ids.isValid(id)) {
        id
    } else {
        diags.error(DiagCode.ID_INVALID, "id: строчные латинские буквы, цифры, «.», «_», «-», до 64 символов", path)
        null
    }

    private fun checkName(name: String, path: String): String? {
        val n = name.trim()
        return if (n.isEmpty() || n.length > 128 || n.any { it.code < 0x20 }) {
            diags.error(DiagCode.NAME_INVALID, "имя пустое, длиннее 128 символов или с управляющими символами", path)
            null
        } else {
            n
        }
    }

    private fun domain(v: String, path: String): String? = Host.normalizeDomain(v) ?: run {
        diags.error(DiagCode.DOMAIN_INVALID, "не доменное имя (IDN — в punycode)", path)
        null
    }

    private fun keyword(v: String, path: String): String? {
        val k = v.trim().lowercase()
        return if (k.isEmpty() || k.length > 253 || k.any { it.isWhitespace() }) {
            diags.error(DiagCode.DOMAIN_INVALID, "ключевое слово домена пустое или с пробелами", path)
            null
        } else {
            k
        }
    }

    private fun cidr(v: String, path: String): Cidr? {
        val parsed = Cidr.parse(v.trim()) ?: run {
            diags.error(DiagCode.CIDR_INVALID, "не подсеть вида «адрес/длина»", path)
            return null
        }
        if (parsed.hadHostBits) diags.info(DiagCode.CIDR_HOST_BITS, "биты хоста обнулены: ${parsed.cidr} (смысл подсети тот же)", path)
        return parsed.cidr
    }

    private fun geo(v: String, path: String): String? {
        val c = v.trim().lowercase()
        return if (RoutingValidator.isValidGeoCode(c)) {
            c
        } else {
            diags.error(DiagCode.GEO_CODE_INVALID, "неверный гео-код", path)
            null
        }
    }

    private fun packages(items: List<Pair<String, String>>): List<String> = items.mapNotNull { (v, p) ->
        if (RoutingValidator.isValidPackage(v)) {
            v
        } else {
            diags.error(DiagCode.PACKAGE_INVALID, "не имя пакета Android", p)
            null
        }
    }

    private fun <E> named(v: String, path: String, values: Map<String, E>): E? = values[v] ?: run {
        diags.error(DiagCode.VALUE_UNKNOWN, "допустимо: ${values.keys.joinToString()}", path)
        null
    }

    companion object {
        val PROTOCOLS = mapOf(
            "vless" to ProtocolKind.VLESS,
            "trojan" to ProtocolKind.TROJAN,
            "shadowsocks" to ProtocolKind.SHADOWSOCKS,
            "hysteria2" to ProtocolKind.HYSTERIA2,
        )
        val FLOWS = VlessFlow.entries.associateBy { it.wire }
        val SS_METHODS = ShadowsocksMethod.entries.associateBy { it.wire }
        val TRANSPORTS = mapOf(
            "tcp" to TransportKind.TCP,
            "websocket" to TransportKind.WEBSOCKET,
            "grpc" to TransportKind.GRPC,
            "xhttp" to TransportKind.XHTTP,
            "httpupgrade" to TransportKind.HTTPUPGRADE,
            "native" to TransportKind.NATIVE,
        )
        val XHTTP_MODES = XHttpMode.entries.associateBy { it.wire }
        val CONGESTIONS = Hysteria2Congestion.entries.associateBy { it.wire }
        val BBR_PROFILES = BbrProfile.entries.associateBy { it.wire }
        val HOP_MODES = HopMode.entries.associateBy { it.wire }
        val SECURITIES = mapOf("none" to SecurityKind.NONE, "tls" to SecurityKind.TLS, "reality" to SecurityKind.REALITY)
        val FINGERPRINTS = TlsFingerprint.entries.associateBy { it.wire }
        val ACTIONS = mapOf("direct" to RouteAction.DIRECT, "proxy" to RouteAction.PROXY, "block" to RouteAction.BLOCK)
        val RESOLUTIONS = mapOf("never" to DomainResolution.NEVER, "if_no_domain_match" to DomainResolution.IF_NO_DOMAIN_MATCH)
        val PROTOCOLS_NET = mapOf("tcp" to TransportProtocol.TCP, "udp" to TransportProtocol.UDP)
        val NETWORKS = mapOf(
            "wifi" to NetworkKind.WIFI,
            "mobile" to NetworkKind.MOBILE,
            "ethernet" to NetworkKind.ETHERNET,
            "other" to NetworkKind.OTHER,
        )
        val STRATEGIES = mapOf(
            "dual" to DnsStrategy.DUAL,
            "prefer_ipv4" to DnsStrategy.PREFER_IPV4,
            "prefer_ipv6" to DnsStrategy.PREFER_IPV6,
            "ipv4_only" to DnsStrategy.IPV4_ONLY,
            "ipv6_only" to DnsStrategy.IPV6_ONLY,
        )
    }
}
