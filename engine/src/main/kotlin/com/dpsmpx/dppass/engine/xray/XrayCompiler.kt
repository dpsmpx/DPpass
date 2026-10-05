package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.routing.AppLowering
import com.dpsmpx.dppass.routing.Conditions
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.DnsRoute
import com.dpsmpx.dppass.routing.DnsServer
import com.dpsmpx.dppass.routing.DnsStrategy
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.DomainResolution
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.TransportProtocol
import java.util.Base64

/**
 * IR → JSON Xray 26.9.30 ([XrayBackend]; работа 2 этапа 2 `ROADMAP`).
 *
 * Обязан сохранить смысл IR или отказать с путём (D-05). Всё, что ниже
 * названо «отказ», — то, что Xray принял бы, но понял иначе или молча
 * проигнорировал; `xray run -test` такого не ловит (он собирает
 * конфигурацию, но не соединяется), поэтому проверка — здесь.
 *
 * Устройство результата:
 * - исходящие: `proxy` (профиль), `direct`, `block` и, с TUN, `dns-out`;
 *   первым стоит исходящий действия по умолчанию — его Xray берёт, когда
 *   ни одно правило не сработало (`app/proxyman/outbound/outbound.go`);
 * - правила: сначала служебные (перехват DNS из TUN, маршрут запросов
 *   каждого DNS-сервера), затем правила пользователя по порядку, с тегом
 *   правила = id; правила, перенесённые на уровень VpnService
 *   (`AppLowering`), в ядро не попадают;
 * - вход TUN с распознаванием имени (TLS SNI, HTTP Host, QUIC) только для
 *   маршрутизации (`routeOnly`): правила по домену видят имя, а
 *   соединение идёт на тот адрес, который выбрало приложение;
 * - журнал ядра выключен: журнал DPpass — только `Logger` с
 *   редактированием (D-11), а журнал доступа Xray пишет адреса назначения;
 * - счётчики трафика исходящих включены — из них `TrafficStats` (D-25).
 *
 * Коды geoip/geosite и атрибуты списков сверяются с набором геоданных
 * ядра ([geodata], D-27): кода нет — отказ с путём правила
 * (`GEO_CODE_UNKNOWN`), набора нет — отказ `GEODATA_UNAVAILABLE`. Без
 * набора ([GeodataCodes.Unchecked]: хост, `cli`, эталоны) коды проверяет
 * само ядро.
 *
 * Конфигурация содержит секреты: наружу — только через
 * [CompiledConfig.payloadForEngine].
 */
class XrayCompiler(
    override val capabilities: EngineCapabilities = XrayBackend.CAPABILITIES,
    private val geodata: GeodataCodes = GeodataCodes.Unchecked,
) : BackendCompiler {
    override fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig> {
        val problems = CapabilityChecker.check(ir, capabilities, plan).toMutableList()
        if (problems.any { it.isError }) return Outcome.Failure(problems)
        val index = ir.profiles.indexOfFirst { it.id == plan.profileId }
        val profile = ir.profiles[index]
        val build = Build(problems, geodata)

        val proxy = build.proxyOutbound(profile, "$.profiles[$index]")
        val dns = build.dns(ir.dns)
        val routing = build.routing(ir, plan.withTun)
        if (problems.any { it.isError }) return Outcome.Failure(problems)

        val terminal = mapOf(
            RouteAction.PROXY to proxy,
            RouteAction.DIRECT to build.directOutbound(ir.dns.strategy),
            RouteAction.BLOCK to blockOutbound(),
        )
        // Первый исходящий — действие по умолчанию (см. KDoc класса).
        val order = listOf(ir.routing.defaultAction) + RouteAction.entries.filter { it != ir.routing.defaultAction }
        val outbounds = order.map { terminal.getValue(it) } + listOfNotNull(dnsOutbound().takeIf { plan.withTun })

        val doc = Json.obj(
            "log" to Json.obj("loglevel" to Json.str("none"), "dnsLog" to Json.bool(false)),
            "dns" to dns,
            "routing" to routing,
            "inbounds" to Json.arr(listOfNotNull(tunInbound().takeIf { plan.withTun })),
            "outbounds" to Json.arr(outbounds),
            // Счётчики исходящих (`outbound>>>proxy>>>traffic>>>…`): по ним мост отдаёт
            // TrafficStats сессии (D-25); без них запуск отвергается, а не врёт нулями.
            "stats" to Json.obj(),
            "policy" to Json.obj(
                "system" to Json.obj("statsOutboundUplink" to Json.bool(true), "statsOutboundDownlink" to Json.bool(true)),
            ),
        )
        val payload = Json.write(doc, pretty = true) + "\n"
        return Outcome.Success(
            CompiledConfig(capabilities.backendId, capabilities.backendVersion, profile.id, payload, Checksums.sha256(payload)),
            problems,
        )
    }

    /** Одна компиляция: находки копятся в [problems] — отказ виден весь, а не первой ошибкой. */
    private class Build(private val problems: MutableList<Diagnostic>, private val geodata: GeodataCodes) {
        fun reject(code: DiagCode, message: String, path: String) {
            problems += Diagnostic.error(code, "${XrayBackend.ID} ${XrayBackend.VERSION}: $message", path)
        }

        /** Коды geoip/geosite условия — против набора геоданных ядра (D-27). */
        private fun checkGeo(geoSites: List<String>, geoIps: List<String>, path: String) {
            when (val g = geodata) {
                GeodataCodes.Unchecked -> Unit
                is GeodataCodes.Missing -> for ((field, codes) in listOf("geosite" to geoSites, "geoip" to geoIps)) {
                    if (codes.isEmpty()) continue
                    reject(DiagCode.GEODATA_UNAVAILABLE, "набора геоданных нет (${g.reason}) — условие $field не выполнить", "$path.$field")
                }
                is GeodataCodes.Installed -> {
                    val m = g.manifest
                    for (code in geoIps.filter { it !in m.geoIp }) {
                        reject(DiagCode.GEO_CODE_UNKNOWN, "geoip:$code — такого кода нет в наборе геоданных (${m.summary})", "$path.geoip")
                    }
                    for (entry in geoSites) {
                        val code = entry.substringBefore('@')
                        val attrs = entry.split('@').drop(1)
                        val known = m.geoSite[code]
                        if (known == null) {
                            reject(DiagCode.GEO_CODE_UNKNOWN, "geosite:$code — такого списка нет в наборе геоданных (${m.summary})", "$path.geosite")
                            continue
                        }
                        // Xray выбирает правила списка по атрибутам; атрибута, которого в списке
                        // нет, не найдёт ни одно правило — условие молча пустое.
                        for (a in attrs.filter { it !in known }) {
                            reject(DiagCode.GEO_CODE_UNKNOWN, "geosite:$entry — у списка $code нет атрибута @$a (${m.summary})", "$path.geosite")
                        }
                    }
                }
            }
        }

        // ---- исходящий профиля ----

        fun proxyOutbound(p: ServerProfile, path: String): JsonObject {
            val address = JsonString(p.endpoint.host.toString())
            val port = Json.num(p.endpoint.port)
            return when (val proto = p.protocol) {
                is ProtocolSpec.Vless -> Json.obj(
                    "tag" to Json.str(XrayBackend.TAG_PROXY),
                    "protocol" to Json.str("vless"),
                    "settings" to Json.obj(
                        "address" to address,
                        "port" to port,
                        "id" to Json.str(proto.id.reveal().lowercase()),
                        // Без шифрования VLESS (его в IR нет) Xray требует явного "none".
                        "encryption" to Json.str("none"),
                        // Vision: UDP/443 (QUIC) Xray отвергает — браузер уходит на TCP. Это
                        // свойство самого flow; вариант -udp443 изменил бы поведение молча.
                        "flow" to Json.str("xtls-rprx-vision").takeIf { proto.flow == VlessFlow.VISION },
                    ),
                    "streamSettings" to stream(p, path),
                )
                is ProtocolSpec.Trojan -> Json.obj(
                    "tag" to Json.str(XrayBackend.TAG_PROXY),
                    "protocol" to Json.str("trojan"),
                    "settings" to Json.obj("address" to address, "port" to port, "password" to Json.str(proto.password.reveal())),
                    "streamSettings" to stream(p, path),
                )
                is ProtocolSpec.Shadowsocks -> Json.obj(
                    "tag" to Json.str(XrayBackend.TAG_PROXY),
                    "protocol" to Json.str("shadowsocks"),
                    "settings" to Json.obj(
                        "address" to address,
                        "port" to port,
                        "method" to Json.str(proto.method.wire),
                        "password" to Json.str(ssKey(proto, path)),
                    ),
                    "streamSettings" to stream(p, path),
                )
                is ProtocolSpec.Hysteria2 -> hysteria(p, proto, address, port, path)
            }
        }

        /**
         * Ключ SS-2022 — base64 со стандартным дополнением: Xray читает его
         * `base64.StdEncoding`, а не сумев — молча берёт байты строки как ключ,
         * и «:» делит строку на несколько ключей (`proxy/shadowsocks_2022/kdf.go`).
         * Поэтому ключ раскодируется здесь и записывается заново.
         */
        private fun ssKey(proto: ProtocolSpec.Shadowsocks, path: String): String {
            val bytes = runCatching { Base64.getDecoder().decode(proto.password.reveal()) }.getOrNull()
            if (bytes == null) {
                reject(DiagCode.PASSWORD_FORMAT_INVALID, "ключ ${proto.method.wire} — не base64", "$path.protocol.password")
                return ""
            }
            return Base64.getEncoder().encodeToString(bytes)
        }

        /**
         * Hysteria2 в Xray — протокол `hysteria` (`version: 2`) с транспортом
         * `hysteria`; пароль — `hysteriaSettings.auth`, Salamander —
         * `finalmask.udp`. ALPN у него всегда `h3`, а отпечаток TLS не
         * используется (`transport/internet/hysteria/dialer.go`): иное в IR
         * Xray проигнорировал бы молча — отказ.
         */
        private fun hysteria(p: ServerProfile, proto: ProtocolSpec.Hysteria2, address: JsonValue, port: JsonValue, path: String): JsonObject {
            val tls = p.security as? SecuritySpec.Tls
            if (tls == null) {
                reject(DiagCode.SECURITY_REQUIRED, "Hysteria2 — только с TLS", "$path.security")
            } else {
                if (tls.alpn.any { it != "h3" }) {
                    reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "у Hysteria2 ALPN всегда h3, другое значение не применится", "$path.security.alpn")
                }
                if (tls.fingerprint != null) {
                    reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "у Hysteria2 нет отпечатка TLS — fingerprint не применится", "$path.security.fingerprint")
                }
            }
            val obfs = proto.obfsPassword?.reveal()
            // Salamander требует ключ не короче 4 байт; Xray проверяет это только при соединении.
            if (obfs != null && obfs.toByteArray(Charsets.UTF_8).size < 4) {
                reject(DiagCode.PASSWORD_FORMAT_INVALID, "пароль obfs (Salamander) — не короче 4 байт", "$path.protocol.obfs_password")
            }
            val stream = Json.obj(
                "network" to Json.str("hysteria"),
                "hysteriaSettings" to Json.obj("version" to Json.num(2), "auth" to Json.str(proto.password.reveal())),
                "security" to Json.str("tls"),
                "tlsSettings" to Json.obj("serverName" to Json.str(tls?.serverName)),
                "finalmask" to obfs?.let {
                    Json.obj("udp" to Json.arr(listOf(Json.obj("type" to Json.str("salamander"), "settings" to Json.obj("password" to Json.str(it))))))
                },
            )
            return Json.obj(
                "tag" to Json.str(XrayBackend.TAG_PROXY),
                "protocol" to Json.str("hysteria"),
                "settings" to Json.obj("version" to Json.num(2), "address" to address, "port" to port),
                "streamSettings" to stream,
            )
        }

        private fun stream(p: ServerProfile, path: String): JsonObject {
            val vision = (p.protocol as? ProtocolSpec.Vless)?.flow == VlessFlow.VISION
            // Xray проверяет это только в работе (proxy/vless/outbound): -test такое пропускает.
            if (vision && (p.transport !is TransportSpec.Tcp || p.security is SecuritySpec.None)) {
                reject(DiagCode.FLOW_REQUIRES_TCP_TLS, "flow vision — только поверх tcp с TLS или REALITY", "$path.protocol.flow")
            }
            val out = LinkedHashMap<String, JsonValue>()
            out["network"] = JsonString(
                when (p.transport) {
                    TransportSpec.Tcp -> "raw"
                    is TransportSpec.WebSocket -> "ws"
                    is TransportSpec.Grpc -> "grpc"
                    is TransportSpec.XHttp -> "xhttp"
                    is TransportSpec.HttpUpgrade -> "httpupgrade"
                    TransportSpec.Native -> {
                        reject(DiagCode.TRANSPORT_PROTOCOL_MISMATCH, "transport native — только у Hysteria2", "$path.transport")
                        "raw"
                    }
                },
            )
            when (val t = p.transport) {
                is TransportSpec.WebSocket -> out["wsSettings"] = Json.obj("path" to Json.str(t.path), "host" to Json.str(t.host))
                is TransportSpec.Grpc -> out["grpcSettings"] = Json.obj("serviceName" to Json.str(t.serviceName))
                is TransportSpec.XHttp ->
                    out["xhttpSettings"] = Json.obj("path" to Json.str(t.path), "host" to Json.str(t.host), "mode" to Json.str(t.mode.wire))
                is TransportSpec.HttpUpgrade -> out["httpupgradeSettings"] = Json.obj("path" to Json.str(t.path), "host" to Json.str(t.host))
                TransportSpec.Tcp, TransportSpec.Native -> Unit
            }
            when (val s = p.security) {
                SecuritySpec.None -> out["security"] = JsonString("none")
                // Проверку сертификата не отключить: allowInsecure в 26.9.30 — ошибка
                // сборки, а пиннинга в IR нет; поля, выключающие проверку, не пишутся (D-11, T5).
                is SecuritySpec.Tls -> {
                    out["security"] = JsonString("tls")
                    out["tlsSettings"] = Json.obj(
                        "serverName" to Json.str(s.serverName),
                        "alpn" to s.alpn.takeIf { it.isNotEmpty() }?.let(Json::strings),
                        "fingerprint" to Json.str(s.fingerprint?.wire),
                    )
                }
                is SecuritySpec.Reality -> {
                    out["security"] = JsonString("reality")
                    out["realitySettings"] = Json.obj(
                        "serverName" to Json.str(s.serverName),
                        "password" to Json.str(s.publicKey),
                        "shortId" to Json.str(s.shortId.reveal()),
                        "fingerprint" to Json.str(s.fingerprint.wire),
                        "spiderX" to Json.str(s.spiderX),
                    )
                }
            }
            return JsonObject(out)
        }

        // ---- маршрутизация ----

        fun routing(ir: ConfigIr, withTun: Boolean): JsonObject {
            val lowered = AppLowering.lower(ir.routing)
            val rules = mutableListOf<JsonValue>()
            if (withTun) {
                // Приложения в туннеле спрашивают DNS у адреса TUN; ответ — по DnsPolicy.
                rules += Json.obj(
                    "ruleTag" to Json.str("${XrayBackend.SYSTEM_PREFIX}dns-hijack"),
                    "inboundTag" to Json.strings(listOf(XrayBackend.TAG_TUN_IN)),
                    "ip" to Json.strings(listOf(XrayBackend.TUN_DNS4)),
                    "port" to Json.str("53"),
                    "outboundTag" to Json.str(XrayBackend.TAG_DNS_OUT),
                )
            }
            // Запросы DNS-серверов, которые идут через диспетчер ядра, — до правил
            // пользователя: иначе правило direct увело бы имена мимо туннеля (T4).
            for (s in ir.dns.servers.distinctBy { it.id }) {
                if (!viaDispatcher(s)) continue
                rules += Json.obj(
                    "ruleTag" to Json.str("${XrayBackend.SYSTEM_PREFIX}dns:${s.id}"),
                    "inboundTag" to Json.strings(listOf(XrayBackend.dnsTag(s.id))),
                    "outboundTag" to Json.str(if (s.route == DnsRoute.TUNNEL) XrayBackend.TAG_PROXY else XrayBackend.TAG_DIRECT),
                )
            }
            for ((i, rule) in lowered.engineRules.withIndex()) {
                val at = "$.routing.rules[${ir.routing.rules.indexOf(rule).takeIf { it >= 0 } ?: i}]"
                rules += userRule(rule.id.value, rule.conditions, XrayBackend.outboundTag(rule.action), at)
            }
            return Json.obj(
                "domainStrategy" to Json.str(domainStrategy(ir.routing.domainResolution, withTun)),
                "rules" to Json.arr(rules),
            )
        }

        /**
         * `if_no_domain_match`: повтор по IP, только когда у соединения нет
         * адреса (`RouteEvaluator`). Из TUN адрес есть всегда, и смысл IR —
         * один проход (`AsIs`). `IPIfNonMatch` Xray повторяет проход и при
         * известном адресе, подменяя его адресами из своего DNS
         * (`app/router/router.go`, `features/routing/dns/context.go`), —
         * это изменило бы смысл молча.
         */
        private fun domainStrategy(r: DomainResolution, withTun: Boolean): String = when {
            r == DomainResolution.NEVER || withTun -> "AsIs"
            else -> "IPIfNonMatch"
        }

        private fun userRule(id: String, c: Conditions, outbound: String, path: String): JsonObject {
            if (c.apps.isNotEmpty()) {
                reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "правило с приложениями в ядре", "$path.apps")
            }
            if (c.networks.isNotEmpty()) {
                reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "условие network", "$path.network")
            }
            checkGeo(c.geoSites, c.geoIps, path)
            val names = c.domains.map(::domainRule) + c.geoSites.map { "geosite:$it" }
            val ips = c.ipCidrs.map { it.toString() } + c.geoIps.map { "geoip:$it" }
            val network = when (c.protocols) {
                emptySet<TransportProtocol>() -> null
                setOf(TransportProtocol.TCP) -> "tcp"
                setOf(TransportProtocol.UDP) -> "udp"
                else -> "tcp,udp"
            }
            return Json.obj(
                "ruleTag" to Json.str(id),
                "domain" to names.takeIf { it.isNotEmpty() }?.let(Json::strings),
                "ip" to ips.takeIf { it.isNotEmpty() }?.let(Json::strings),
                "port" to c.ports.takeIf { it.isNotEmpty() }?.let { ports -> Json.str(ports.joinToString(",")) },
                "network" to Json.str(network),
                "outboundTag" to Json.str(outbound),
            )
        }

        // ---- DNS ----

        /**
         * Правила DNS IR — «первое сработавшее правило решает, других
         * серверов имя не видит». В Xray так: на каждое правило — своя
         * запись сервера с его именами, `finalQuery` (дальше не спрашивать)
         * и `skipFallback` (не быть запасным для чужих имён), в порядке
         * правил; сервер по умолчанию — единственный запасной
         * (`app/dns/dns.go`, `sortClients`). Отказ сервера не уводит имя к
         * другому серверу — в том числе мимо туннеля.
         */
        fun dns(policy: DnsPolicy): JsonObject {
            val servers = mutableListOf<JsonValue>()
            for ((i, rule) in policy.rules.withIndex()) {
                checkGeo(rule.geoSites, emptyList(), "$.dns.rules[$i]")
                val s = policy.server(rule.serverId) ?: continue
                val names = rule.domains.map(::domainRule) + rule.geoSites.map { "geosite:$it" }
                val base = dnsServer(s, "$.dns.servers[${policy.servers.indexOf(s)}]") ?: continue
                servers += JsonObject(
                    base.fields + mapOf(
                        "domains" to Json.strings(names),
                        "skipFallback" to Json.bool(true),
                        "finalQuery" to Json.bool(true),
                    ),
                )
            }
            val default = policy.server(policy.defaultServerId)
            if (default != null) {
                dnsServer(default, "$.dns.servers[${policy.servers.indexOf(default)}]")?.let {
                    servers += JsonObject(it.fields + mapOf("finalQuery" to Json.bool(true)))
                }
            }
            return Json.obj(
                "tag" to Json.str(XrayBackend.TAG_DNS_DEFAULT),
                "servers" to Json.arr(servers),
                "queryStrategy" to Json.str(queryStrategy(policy.strategy)),
                "disableFallbackIfMatch" to Json.bool(true),
            )
        }

        /** Сервер в форме Xray: адрес, порт, тег (по нему — маршрут запросов). */
        private fun dnsServer(s: DnsServer, path: String): JsonObject? {
            val tunnel = s.route == DnsRoute.TUNNEL
            val (address, port) = when (val t = s.transport) {
                // Классический UDP Xray всегда шлёт через диспетчер; напрямую — правилом на direct,
                // а адрес по имени пришлось бы резолвить тем же DNS — только IP.
                is DnsTransport.Udp -> {
                    if (!tunnel && t.server.host !is Host.Ip) {
                        reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "DNS-сервер UDP напрямую — только по IP-адресу", path)
                        return null
                    }
                    t.server.host.toString() to t.server.port
                }
                is DnsTransport.Tcp -> "${if (tunnel) "tcp" else "tcp+local"}://${t.server}" to null
                is DnsTransport.Https -> (if (tunnel) t.url else "https+local://" + t.url.removePrefix("https://")) to null
                is DnsTransport.Tls -> {
                    reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "DNS-over-TLS в Xray нет", path)
                    return null
                }
                DnsTransport.System -> "localhost" to null
            }
            return Json.obj(
                "address" to Json.str(address),
                "port" to port?.let(Json::num),
                "tag" to Json.str(XrayBackend.dnsTag(s.id)),
            )
        }

        /**
         * Стратегия адресов: приложения сами спрашивают A и AAAA, поэтому
         * `prefer_*` отвечает на оба (`UseIP`), а предпочтение действует там,
         * где адрес выбирает ядро (исходящий `direct`, [directOutbound]).
         */
        private fun queryStrategy(s: DnsStrategy): String = when (s) {
            DnsStrategy.DUAL, DnsStrategy.PREFER_IPV4, DnsStrategy.PREFER_IPV6 -> "UseIP"
            DnsStrategy.IPV4_ONLY -> "UseIPv4"
            DnsStrategy.IPV6_ONLY -> "UseIPv6"
        }

        /**
         * `direct`: имя назначения ядро резолвит своим DNS по DnsPolicy и при
         * отказе не уходит к системному резолверу (`ForceIP*`; `AsIs` и
         * `UseIP*` молча спросили бы систему — T4).
         */
        fun directOutbound(s: DnsStrategy): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_DIRECT),
            "protocol" to Json.str("freedom"),
            "streamSettings" to Json.obj(
                "sockopt" to Json.obj(
                    "domainStrategy" to Json.str(
                        when (s) {
                            DnsStrategy.DUAL -> "ForceIP"
                            DnsStrategy.PREFER_IPV4 -> "ForceIPv4v6"
                            DnsStrategy.PREFER_IPV6 -> "ForceIPv6v4"
                            DnsStrategy.IPV4_ONLY -> "ForceIPv4"
                            DnsStrategy.IPV6_ONLY -> "ForceIPv6"
                        },
                    ),
                ),
            ),
        )
    }

    private companion object {
        fun domainRule(m: DomainMatcher): String = when (m) {
            is DomainMatcher.Full -> "full:${m.name}"
            is DomainMatcher.Suffix -> "domain:${m.suffix}"
            is DomainMatcher.Keyword -> "keyword:${m.keyword}"
        }

        /** Классический UDP и «удалённые» TCP и DoH Xray шлёт через диспетчер; `+local` и система — мимо него. */
        fun viaDispatcher(s: DnsServer): Boolean = when (s.transport) {
            is DnsTransport.Udp -> true
            is DnsTransport.Tcp, is DnsTransport.Https -> s.route == DnsRoute.TUNNEL
            is DnsTransport.Tls, DnsTransport.System -> false
        }

        fun blockOutbound(): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_BLOCK),
            "protocol" to Json.str("blackhole"),
            "settings" to Json.obj("response" to Json.obj("type" to Json.str("none"))),
        )

        /** Перехваченные запросы A/AAAA отвечает DNS ядра; прочие типы — пустой NOERROR. */
        fun dnsOutbound(): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_DNS_OUT),
            "protocol" to Json.str("dns"),
            "settings" to Json.obj(
                "rules" to Json.arr(
                    listOf(
                        Json.obj("action" to Json.str("hijack"), "qType" to Json.str("1,28")),
                        Json.obj("action" to Json.str("return"), "rCode" to Json.num(0)),
                    ),
                ),
            ),
        )

        fun tunInbound(): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_TUN_IN),
            "protocol" to Json.str("tun"),
            // Имя — всегда: без него Xray перебирает интерфейсы системы, а на Android это запрещено (XrayBackend.TUN_NAME).
            "settings" to Json.obj("name" to Json.str(XrayBackend.TUN_NAME), "mtu" to Json.num(XrayBackend.TUN_MTU)),
            "sniffing" to Json.obj(
                "enabled" to Json.bool(true),
                "destOverride" to Json.strings(listOf("http", "tls", "quic")),
                "routeOnly" to Json.bool(true),
            ),
        )
    }
}
