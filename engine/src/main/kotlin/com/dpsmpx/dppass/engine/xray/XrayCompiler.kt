package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.CountRange
import com.dpsmpx.dppass.config.HopMode
import com.dpsmpx.dppass.config.Hysteria2Hop
import com.dpsmpx.dppass.config.Hysteria2Quic
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.config.XHttpExtra
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.LocalProxySpec
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SystemTun
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
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.SplitSites
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
 * набора ([GeodataCodes.Unchecked]: хост) коды не сверяются: в `cli` ядра
 * нет, эталоны ядро проверяет на синтетическом наборе со всеми их кодами.
 * Несколько атрибутов сверяются сочетанием: ни у одного правила списка
 * нет их всех сразу — тоже отказ (`docs/CONFIG_FORMAT.md`, §4).
 *
 * Перехват DNS из TUN — запросы к адресу TUN ([XrayBackend.TUN_DNS4]: его
 * Android даёт приложениям). На Linux ([dnsHijackAnyAddress], D-74)
 * резолвер системы не перенастраивается, и запрос на порт 53 любого
 * адреса правилами `ip rule` приходит в TUN — ядро перехватывает его
 * весь, иначе запрос к резолверу роутера ушёл бы `direct` мимо туннеля.
 * На Windows (D-97) так же: DNS адаптера и фильтр WFP `dns` ведут в TUN
 * запросы на порт 53 к любому адресу.
 *
 * TUN ядра (Windows, [CompilePlan.systemTun], D-97) — вход TUN с адресами,
 * маршрутами и DNS адаптера, привязкой сокетов ядра к физическому
 * интерфейсу (`autoOutboundsInterface`) и фильтрами WFP `dns` и
 * `misconfigtun`: вне TUN не уходят ни DNS, ни версия IP без маршрутов в
 * него. Политика моста пропускает эти поля только на Windows.
 *
 * Конфигурация содержит секреты: наружу — только через
 * [CompiledConfig.payloadForEngine].
 */
class XrayCompiler(
    override val capabilities: EngineCapabilities = XrayBackend.CAPABILITIES,
    private val geodata: GeodataCodes = GeodataCodes.Unchecked,
    private val dnsHijackAnyAddress: Boolean = false,
) : BackendCompiler {
    override fun checkSplitSites(sites: SplitSites): List<Diagnostic> {
        val problems = mutableListOf<Diagnostic>()
        Build(problems, geodata, dnsHijackAnyAddress).splitSiteRules(sites, withTun = true)
        return problems
    }

    override fun checkGeoCodes(geoSites: List<String>, geoIps: List<String>, path: String): List<Diagnostic> {
        val problems = mutableListOf<Diagnostic>()
        Build(problems, geodata, dnsHijackAnyAddress).checkGeo(geoSites, geoIps, path)
        return problems
    }

    override fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig> {
        val problems = CapabilityChecker.check(ir, capabilities, plan).toMutableList()
        // Локальный прокси (D-95) — вместо VPN, а не рядом с ним: при TUN приложение вне
        // туннеля (D-38), узнав пароль, обошло бы через него выбор приложений.
        if (plan.local != null && plan.withTun) {
            problems += Diagnostic.error(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "локальный прокси — только без VPN (D-95), а в плане есть TUN", "$.inbounds")
        }
        if (plan.systemTun != null && !plan.withTun) problems += systemTunWithoutTun()
        if (problems.any { it.isError }) return Outcome.Failure(problems)
        val index = ir.profiles.indexOfFirst { it.id == plan.profileId }
        val profile = ir.profiles[index]
        val build = Build(problems, geodata, dnsHijackAnyAddress)

        // Разбиение ClientHello (D-68): только где он есть и идёт по TCP; иначе — сказать, а не молча (D-05).
        val split = plan.splitClientHello && splittable(profile)
        if (plan.splitClientHello && !split) {
            problems += Diagnostic.warning(
                DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED,
                "${XrayBackend.ID} ${XrayBackend.VERSION}: у «${profile.name}» нет TLS поверх TCP — разбивать нечего, подключение как есть",
                "$.profiles[$index]",
            )
        }
        val proxy = build.proxyOutbound(profile, "$.profiles[$index]").let { if (split) viaSplit(it) else it }
        val dns = build.dns(ir.dns)
        val routing = build.routing(ir, plan.withTun, plan.share, plan.splitSites)
        if (problems.any { it.isError }) return Outcome.Failure(problems)

        val terminal = mapOf(
            RouteAction.PROXY to proxy,
            RouteAction.DIRECT to build.directOutbound(ir.dns.strategy),
            RouteAction.BLOCK to blockOutbound(),
        )
        // Первый исходящий — действие по умолчанию (см. KDoc класса).
        val order = listOf(ir.routing.defaultAction) + RouteAction.entries.filter { it != ir.routing.defaultAction }
        val outbounds = order.map { terminal.getValue(it) } + listOfNotNull(
            dnsOutbound().takeIf { plan.withTun },
            build.directShareOutbound(ir.dns.strategy).takeIf { plan.share != null },
            splitOutbound().takeIf { split },
            build.directSplitOutbound(ir.dns.strategy).takeIf { !plan.splitSites.isEmpty },
        )

        val inbounds = listOfNotNull(tunInbound(plan.systemTun).takeIf { plan.withTun }, plan.local?.let(::localInbound)) +
            plan.share?.let(::shareInbounds).orEmpty()
        return Outcome.Success(compiled(profile.id, document(dns, routing, inbounds, outbounds)), problems)
    }

    /**
     * Без сервера (D-73): исходящего к серверу нет. `proxy` — прямой выход с
     * разбиением: по его счётчикам мост отдаёт трафик сеанса, и через него
     * идут проба DNS и замер скорости (D-25, D-32, D-61) — в этом режиме это
     * путь с разбиением. Сайты списка — на него (TCP) или в `block` (UDP
     * 443), как в D-72; остальное — `direct` или, если [ServerlessPlan.splitRest],
     * тоже `proxy`. Сервер DNS через туннель здесь не к кому вести — отказ.
     */
    override fun compileServerless(plan: ServerlessPlan): Outcome<CompiledConfig> {
        val problems = mutableListOf<Diagnostic>()
        if (plan.systemTun != null && !plan.withTun) problems += systemTunWithoutTun()
        val build = Build(problems, geodata, dnsHijackAnyAddress)
        for ((i, server) in plan.dns.servers.withIndex()) {
            if (server.route == DnsRoute.TUNNEL) {
                build.reject(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "без сервера DNS-сервер «${server.id}» через туннель вести некуда", "$.dns.servers[$i]")
            }
        }
        val ir = ConfigIr(name = null, profiles = emptyList(), routing = RoutingPolicy(defaultAction = RouteAction.DIRECT), dns = plan.dns)
        val dns = build.dns(plan.dns)
        val routing = build.routing(ir, plan.withTun, splitSites = plan.splitSites, splitTag = XrayBackend.TAG_PROXY)
        if (problems.any { it.isError }) return Outcome.Failure(problems)
        val split = build.directSplitOutbound(plan.dns.strategy, XrayBackend.TAG_PROXY)
        val direct = build.directOutbound(plan.dns.strategy)
        // Первый исходящий — для соединений, которых не взяло ни одно правило (см. KDoc класса).
        val outbounds = (if (plan.splitRest) listOf(split, direct) else listOf(direct, split)) +
            listOfNotNull(blockOutbound(), dnsOutbound().takeIf { plan.withTun })
        val inbounds = listOfNotNull(tunInbound(plan.systemTun).takeIf { plan.withTun })
        return Outcome.Success(compiled(ServerlessPlan.PROFILE_ID, document(dns, routing, inbounds, outbounds)), problems)
    }

    private fun document(dns: JsonObject, routing: JsonObject, inbounds: List<JsonObject>, outbounds: List<JsonObject>): JsonObject = Json.obj(
        "log" to Json.obj("loglevel" to Json.str("none"), "dnsLog" to Json.bool(false)),
        "dns" to dns,
        "routing" to routing,
        "inbounds" to Json.arr(inbounds),
        "outbounds" to Json.arr(outbounds),
        // Счётчики исходящих (`outbound>>>proxy>>>traffic>>>…`): по ним мост отдаёт
        // TrafficStats сессии (D-25); без них запуск отвергается, а не врёт нулями.
        "stats" to Json.obj(),
        "policy" to Json.obj(
            "system" to Json.obj("statsOutboundUplink" to Json.bool(true), "statsOutboundDownlink" to Json.bool(true)),
        ),
    )

    private fun compiled(profileId: ProfileId, doc: JsonObject): CompiledConfig {
        val payload = Json.write(doc, pretty = true) + "\n"
        return CompiledConfig(capabilities.backendId, capabilities.backendVersion, profileId, payload, Checksums.sha256(payload))
    }

    /** Одна компиляция: находки копятся в [problems] — отказ виден весь, а не первой ошибкой. */
    private class Build(
        private val problems: MutableList<Diagnostic>,
        private val geodata: GeodataCodes,
        private val dnsHijackAnyAddress: Boolean,
    ) {
        fun reject(code: DiagCode, message: String, path: String) {
            problems += Diagnostic.error(code, "${XrayBackend.ID} ${XrayBackend.VERSION}: $message", path)
        }

        /** Коды geoip/geosite условия — против набора геоданных ядра (D-27). */
        fun checkGeo(geoSites: List<String>, geoIps: List<String>, path: String) {
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
                        val known = m.siteAttributes(code)
                        if (known == null) {
                            reject(DiagCode.GEO_CODE_UNKNOWN, "geosite:$code — такого списка нет в наборе геоданных (${m.summary})", "$path.geosite")
                            continue
                        }
                        // Xray берёт правила списка, у которых есть каждый из атрибутов сразу
                        // (common/geodata, siteDecoder): атрибута нет в списке или нет правила
                        // со всеми ними — условие молча пустое (D-05).
                        val absent = attrs.filter { it !in known }
                        for (a in absent) {
                            reject(DiagCode.GEO_CODE_UNKNOWN, "geosite:$entry — у списка $code нет атрибута @$a (${m.summary})", "$path.geosite")
                        }
                        if (absent.isEmpty() && !m.siteHasRuleWithAll(code, attrs)) {
                            reject(
                                DiagCode.GEO_CODE_UNKNOWN,
                                "geosite:$entry — в списке $code нет правила со всеми атрибутами ${attrs.distinct().joinToString("") { "@$it" }} " +
                                    "сразу: ядро берёт только такие, и условие не сработало бы ни разу (${m.summary})",
                                "$path.geosite",
                            )
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
                // Устройство раздачи (D-55): вход раздачи другого DPpass — SOCKS5 с паролем
                // (`infra/conf/socks.go`: адрес, порт, user и pass прямо в settings).
                is ProtocolSpec.Socks -> Json.obj(
                    "tag" to Json.str(XrayBackend.TAG_PROXY),
                    "protocol" to Json.str("socks"),
                    "settings" to Json.obj(
                        "address" to address,
                        "port" to port,
                        "user" to Json.str(proto.user.reveal()),
                        "pass" to Json.str(proto.password.reveal()),
                    ),
                    "streamSettings" to stream(p, path),
                )
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
                // Маски UDP: Salamander и перескок портов (D-107); управление перегрузкой (формат 2,
                // D-37) и прочие параметры QUIC (формат 3) — quicParams. По умолчанию ядра — поля нет.
                "finalmask" to Json.obj(
                    "udp" to udpMasks(obfs, proto.hop).takeIf { it.isNotEmpty() }?.let(Json::arr),
                    "quicParams" to quicParams(proto).takeIf { it.fields.isNotEmpty() },
                ).takeIf { it.fields.isNotEmpty() },
            )
            return Json.obj(
                "tag" to Json.str(XrayBackend.TAG_PROXY),
                "protocol" to Json.str("hysteria"),
                "settings" to Json.obj("version" to Json.num(2), "address" to address, "port" to port),
                "streamSettings" to stream,
            )
        }

        /** Маски UDP Hysteria2: Salamander (D-37) и перескок портов `udphop` (D-107). */
        private fun udpMasks(obfs: String?, hop: Hysteria2Hop?): List<JsonObject> = listOfNotNull(
            obfs?.let { Json.obj("type" to Json.str("salamander"), "settings" to Json.obj("password" to Json.str(it))) },
            hop?.let { h ->
                Json.obj(
                    "type" to Json.str("udphop"),
                    "settings" to Json.obj(
                        "mode" to Json.str(HopMode.entries.filter { it in h.modes }.joinToString(",") { it.xray }),
                        "remotePorts" to Json.str(h.ports.joinToString(",")),
                        "interval" to h.interval?.let { Json.str(it.toString()) },
                    ),
                )
            },
        )

        /**
         * `quicParams` Hysteria2 (D-37, D-107). Скорость Brutal ядро читает
         * строкой с единицей и делит на 8 (биты в байты): пишется число бит в
         * секунду без единицы — байт в секунду получается ровно столько, сколько в IR.
         */
        private fun quicParams(proto: ProtocolSpec.Hysteria2): JsonObject {
            val q = proto.quic ?: Hysteria2Quic()
            fun flag(on: Boolean): JsonValue? = JsonBool(true).takeIf { on }
            return Json.obj(
                "congestion" to proto.congestion?.let { Json.str(it.wire) },
                "bbrProfile" to q.bbrProfile?.let { Json.str(it.wire) },
                "brutalUp" to q.brutalUp?.let { Json.str((it * 8).toString()) },
                "brutalDown" to q.brutalDown?.let { Json.str((it * 8).toString()) },
                "brutalDisableLossCompensation" to flag(q.brutalDisableLossCompensation),
                "initStreamReceiveWindow" to q.initStreamReceiveWindow?.let(Json::num),
                "maxStreamReceiveWindow" to q.maxStreamReceiveWindow?.let(Json::num),
                "initConnectionReceiveWindow" to q.initConnReceiveWindow?.let(Json::num),
                "maxConnectionReceiveWindow" to q.maxConnReceiveWindow?.let(Json::num),
                "maxIdleTimeout" to q.maxIdleTimeoutSecs?.let(Json::num),
                "keepAlivePeriod" to q.keepAlivePeriodSecs?.let(Json::num),
                "disablePathMTUDiscovery" to flag(q.disablePathMtuDiscovery),
                "disableChromeParrot" to flag(q.disableChromeParrot),
                "disableGSO" to flag(q.disableGso),
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
                is TransportSpec.XHttp -> out["xhttpSettings"] = JsonObject(
                    Json.obj("path" to Json.str(t.path), "host" to Json.str(t.host), "mode" to Json.str(t.mode.wire)).fields + xhttpExtra(t.extra).fields,
                )
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

        /**
         * Настройки XHTTP формата 2 (D-37) — прямо в `xhttpSettings`, а не в
         * `extra`: Xray заменяет настройку содержимым `extra` целиком
         * (`infra/conf/transport_method.go`). Пишутся только заданные; `xmux`
         * — только целиком, как у поставщика: заданный заменяет значения
         * ядра по умолчанию все сразу.
         */
        private fun xhttpExtra(e: XHttpExtra): JsonObject {
            fun range(r: CountRange?): JsonValue? = r?.let { Json.str(it.toString()) }
            return Json.obj(
                "xPaddingBytes" to range(e.xPaddingBytes),
                "scMaxEachPostBytes" to range(e.scMaxEachPostBytes),
                "scMinPostsIntervalMs" to range(e.scMinPostsIntervalMs),
                "noGRPCHeader" to Json.bool(true).takeIf { e.noGrpcHeader },
                "xmux" to e.xmux?.let { x ->
                    Json.obj(
                        "maxConcurrency" to range(x.maxConcurrency),
                        "maxConnections" to range(x.maxConnections),
                        "cMaxReuseTimes" to range(x.cMaxReuseTimes),
                        "hMaxRequestTimes" to range(x.hMaxRequestTimes),
                        "hMaxReusableSecs" to range(x.hMaxReusableSecs),
                        "hKeepAlivePeriod" to x.hKeepAlivePeriod?.let(Json::num),
                    )
                },
            )
        }

        // ---- маршрутизация ----

        fun routing(
            ir: ConfigIr,
            withTun: Boolean,
            share: ShareSpec? = null,
            splitSites: SplitSites = SplitSites.NONE,
            splitTag: String = XrayBackend.TAG_DIRECT_SPLIT,
        ): JsonObject {
            val lowered = AppLowering.lower(ir.routing)
            val rules = mutableListOf<JsonValue>()
            if (share != null) {
                // Раздача (D-51) — только другим устройствам: на входы раздачи пускаются
                // лишь клиенты из подсетей раздачи. Адрес самого телефона и всё вне
                // этих подсетей — приложение телефона (оно может привязать сокет к
                // любому своему адресу); ему отказ, иначе оно обошло бы через прокси
                // политику приложений (D-38).
                rules += Json.obj(
                    "ruleTag" to Json.str("${XrayBackend.SYSTEM_PREFIX}share-guard"),
                    "inboundTag" to Json.strings(shareTags(share)),
                    "source" to Json.strings(shareRefused(share).map { it.toString() }),
                    "outboundTag" to Json.str(XrayBackend.TAG_BLOCK),
                )
            }
            if (withTun) {
                // Приложения в туннеле спрашивают DNS у адреса TUN (на Linux — у любого
                // адреса, см. KDoc класса); ответ — по DnsPolicy.
                rules += Json.obj(
                    "ruleTag" to Json.str("${XrayBackend.SYSTEM_PREFIX}dns-hijack"),
                    "inboundTag" to Json.strings(listOf(XrayBackend.TAG_TUN_IN)),
                    "ip" to Json.strings(listOf(XrayBackend.TUN_DNS4)).takeUnless { dnsHijackAnyAddress },
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
            rules += splitSiteRules(splitSites, withTun, splitTag)
            val user = mutableListOf<JsonObject>()
            for ((i, rule) in lowered.engineRules.withIndex()) {
                val at = "$.routing.rules[${ir.routing.rules.indexOf(rule).takeIf { it >= 0 } ?: i}]"
                user += userRule(rule.id.value, rule.conditions, XrayBackend.outboundTag(rule.action), at)
            }
            // Автоматический раздельный маршрут (D-45): отечественное — напрямую,
            // ПОСЛЕ явных правил пользователя. geosite и geoip — отдельными
            // правилами: в одном правиле Xray соединяет их через И (D-31), а
            // смысл D-45 — ИЛИ (имя ИЛИ адрес отечественные). Коды сверяются с
            // набором (D-27).
            if (ir.routing.automaticDomestic) {
                val site = RouteEvaluator.SITE_RU
                val ip = RouteEvaluator.IP_RU
                checkGeo(listOf(site), emptyList(), "$.routing.automatic_domestic")
                checkGeo(emptyList(), listOf(ip), "$.routing.automatic_domestic")
                user += userRule(
                    "${XrayBackend.SYSTEM_PREFIX}auto-domestic-site",
                    Conditions(geoSites = listOf(site)),
                    XrayBackend.TAG_DIRECT,
                    "$.routing.automatic_domestic",
                )
                user += userRule(
                    "${XrayBackend.SYSTEM_PREFIX}auto-domestic-ip",
                    Conditions(geoIps = listOf(ip)),
                    XrayBackend.TAG_DIRECT,
                    "$.routing.automatic_domestic",
                )
            }
            // Раздача (D-51, T11): «напрямую» для её клиентов — через свой исходящий,
            // закрытый для loopback телефона. Правила те же, что у телефона: перед
            // каждым правилом direct — его копия только для входов раздачи (ruleTag у
            // Xray не повторяется: `dppass:share:<id>`, в id пользователя двоеточий нет);
            // действие по умолчанию direct — последним правилом для них же. Без
            // раздачи конфигурация не меняется.
            for (r in user) {
                if (share != null && (r["outboundTag"] as? JsonString)?.value == XrayBackend.TAG_DIRECT) {
                    rules += JsonObject(
                        r.fields + mapOf(
                            "ruleTag" to JsonString("${XrayBackend.SYSTEM_PREFIX}share:${(r["ruleTag"] as JsonString).value}"),
                            "inboundTag" to Json.strings(shareTags(share)),
                            "outboundTag" to JsonString(XrayBackend.TAG_DIRECT_SHARE),
                        ),
                    )
                }
                rules += r
            }
            if (share != null && ir.routing.defaultAction == RouteAction.DIRECT) {
                rules += Json.obj(
                    "ruleTag" to Json.str("${XrayBackend.SYSTEM_PREFIX}share-default"),
                    "inboundTag" to Json.strings(shareTags(share)),
                    "outboundTag" to Json.str(XrayBackend.TAG_DIRECT_SHARE),
                )
            }
            return Json.obj(
                "domainStrategy" to Json.str(domainStrategy(ir.routing.domainResolution, withTun)),
                "rules" to Json.arr(rules),
            )
        }

        /**
         * Список «Напрямую с разбиением» (D-72) — после служебных правил (DNS
         * — T4) и раньше правил документа: это выбор пользователя на телефоне,
         * и он сильнее документа. UDP 443 — закрыт: в QUIC Initial имя идёт
         * целиком, а `fragment` режет только TLS поверх TCP; приложения
         * переходят на TCP. Только вход TUN: клиенты раздачи — без разбиения,
         * как в D-68. Имя ядро знает из распознавания у входа TUN (`sniffing`).
         * TCP — на [splitTag]: с сервером — `dppass:direct-split`, без сервера —
         * `proxy` (D-73).
         */
        fun splitSiteRules(sites: SplitSites, withTun: Boolean, splitTag: String = XrayBackend.TAG_DIRECT_SPLIT): List<JsonObject> {
            if (sites.isEmpty) return emptyList()
            checkGeo(sites.geoSites, emptyList(), SplitSites.PATH)
            val names = sites.domains.map { "domain:$it" } + sites.geoSites.map { "geosite:$it" }
            val inbound = if (withTun) Json.strings(listOf(XrayBackend.TAG_TUN_IN)) else null
            return listOf(
                Json.obj(
                    "ruleTag" to Json.str(XrayBackend.RULE_SPLIT_QUIC),
                    "inboundTag" to inbound,
                    "domain" to Json.strings(names),
                    "port" to Json.str("443"),
                    "network" to Json.str("udp"),
                    "outboundTag" to Json.str(XrayBackend.TAG_BLOCK),
                ),
                Json.obj(
                    "ruleTag" to Json.str(XrayBackend.RULE_SPLIT_SITES),
                    "inboundTag" to inbound,
                    "domain" to Json.strings(names),
                    "network" to Json.str("tcp"),
                    "outboundTag" to Json.str(splitTag),
                ),
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
         * `direct` для клиентов раздачи (D-51, T11): адрес назначения — не loopback
         * и не «ноль» телефона. Устройству в раздаче службы, которые слушают
         * только 127.0.0.1, недоступны, как и без прокси; из TUN такие адреса не
         * приходят. `finalRules` Xray проверяет и адрес, полученный из имени, — до
         * соединения и после (`proxy/freedom`).
         */
        fun directShareOutbound(s: DnsStrategy): JsonObject = JsonObject(
            directOutbound(s).fields + mapOf(
                "tag" to JsonString(XrayBackend.TAG_DIRECT_SHARE),
                "settings" to Json.obj(
                    "finalRules" to Json.arr(listOf(Json.obj("action" to Json.str("block"), "ip" to Json.strings(SHARE_CLOSED)))),
                ),
            ),
        )

        /**
         * Прямой выход к сайтам списка «Напрямую с разбиением» (D-72): `direct`
         * (тот же резолв имени по DnsPolicy) с разбиением начала TLS, как у
         * выхода разбиения к серверу (D-68): части по [SPLIT_LENGTH] байт, пауза
         * [SPLIT_INTERVAL] мс.
         */
        fun directSplitOutbound(s: DnsStrategy, tag: String = XrayBackend.TAG_DIRECT_SPLIT): JsonObject = JsonObject(
            directOutbound(s).fields + mapOf(
                "tag" to JsonString(tag),
                "settings" to fragmentSettings(),
            ),
        )

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
        /**
         * Есть ли у сервера ClientHello, который идёт по TCP (D-68): TLS или
         * REALITY. У Hysteria2 и XHTTP только по h3 — QUIC (`fragment` Xray
         * режет только TCP); без TLS и у устройства раздачи ClientHello нет.
         */
        fun splittable(p: ServerProfile): Boolean {
            if (p.protocol is ProtocolSpec.Hysteria2 || p.protocol is ProtocolSpec.Socks) return false
            val tls = when (val s = p.security) {
                SecuritySpec.None -> return false
                is SecuritySpec.Reality -> return true
                is SecuritySpec.Tls -> s
            }
            return !(p.transport is TransportSpec.XHttp && tls.alpn == listOf("h3"))
        }

        /** Исходящий `proxy` открывает соединение с сервером через [splitOutbound] (`sockopt.dialerProxy`). */
        fun viaSplit(proxy: JsonObject): JsonObject {
            val stream = proxy.fields["streamSettings"] as JsonObject
            val sockopt = Json.obj("dialerProxy" to Json.str(XrayBackend.TAG_SPLIT))
            return JsonObject(proxy.fields + ("streamSettings" to JsonObject(stream.fields + ("sockopt" to sockopt))))
        }

        /**
         * Прямой выход с разбиением ClientHello (D-68, `proxy/freedom`): первая
         * запись TLS — на записи по [SPLIT_LENGTH] байт, каждая — отдельной
         * записью в сокет с паузой [SPLIT_INTERVAL] мс, то есть отдельным
         * сегментом TCP. Так оба приёма сразу: только сегменты или только
         * записи ТСПУ собирал (FOCI 2025, `docs/research/DPI_DESYNC.md`, §4).
         * Имя сервера он резолвит как и сам `proxy` без разбиения — системой
         * (`AsIs`, D-29); сокеты защищает тот же хук моста (D-25).
         */
        fun splitOutbound(): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_SPLIT),
            "protocol" to Json.str("freedom"),
            "settings" to fragmentSettings(),
        )

        /** Разбивка начала TLS у `freedom` — одна для D-68 и D-72. */
        fun fragmentSettings(): JsonObject = Json.obj(
            "fragment" to Json.obj(
                "packets" to Json.str("tlshello"),
                "length" to Json.str(SPLIT_LENGTH),
                "interval" to Json.str(SPLIT_INTERVAL),
            ),
        )

        /**
         * Длина части и пауза — ориентир, не замер (D-68): ClientHello Chrome
         * (~1,8 КБ с ключом ML-KEM) — ~30 частей и ~60 мс к рукопожатию; имя
         * сервера в нём стоит в случайном месте (порядок расширений случаен),
         * поэтому части мелкие по всей длине. Сверка — на телефоне (`TODO.md`).
         */
        const val SPLIT_LENGTH: String = "40-80"
        const val SPLIT_INTERVAL: String = "1-3"

        /**
         * Куда «напрямую» клиентам раздачи нельзя (T11): loopback и «ноль» (на
         * Linux соединение с 0.0.0.0 приходит на loopback). Адреса IPv4 в виде
         * IPv6 (`::ffff:127.0.0.1`) Xray приводит к IPv4 (`common/net`, `IPAddress`).
         */
        val SHARE_CLOSED: List<String> = listOf("127.0.0.0/8", "0.0.0.0/8", "::1/128", "::/128")

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

        /**
         * Входы раздачи (D-51): SOCKS5 с паролем (и HTTP-прокси на том же порту —
         * так устроен вход socks Xray), по одному на адрес интерфейса раздачи;
         * никогда не `0.0.0.0` и не loopback. UDP — для SOCKS5 UDP ASSOCIATE.
         */
        fun shareInbounds(share: ShareSpec): List<JsonObject> = share.endpoints.map { it.address }.mapIndexed { i, addr ->
            Json.obj(
                "tag" to Json.str(XrayBackend.SHARE_TAG_PREFIX + i),
                "protocol" to Json.str("socks"),
                "listen" to Json.str(addr.toString()),
                "port" to Json.num(share.port),
                "settings" to Json.obj(
                    "auth" to Json.str("password"),
                    "accounts" to Json.arr(share.accounts.map { Json.obj("user" to Json.str(it.user.reveal()), "pass" to Json.str(it.password.reveal())) }),
                    "udp" to Json.bool(true),
                    "ip" to Json.str(addr.toString()),
                ),
                "sniffing" to Json.obj(
                    "enabled" to Json.bool(true),
                    "destOverride" to Json.strings(listOf("http", "tls", "quic")),
                    "routeOnly" to Json.bool(true),
                ),
            )
        }

        /**
         * Вход TUN, который сам создаёт адаптер (Windows, D-97). Фильтр
         * `misconfigtun` всегда: он закрывает только версию IP, у которой нет
         * маршрутов в TUN, — с маршрутами обеих он ничего не меняет.
         */
        fun systemTunSettings(system: SystemTun): JsonObject = Json.obj(
            "name" to Json.str(XrayBackend.TUN_NAME),
            "mtu" to Json.num(XrayBackend.TUN_MTU),
            "gateway" to Json.strings(system.addresses.map { it.toString() }),
            "dns" to Json.strings(system.dns.map { it.toString() }),
            "autoSystemRoutingTable" to Json.strings(system.routes.map { it.toString() }),
            "autoOutboundsInterface" to Json.str(system.outboundsInterface ?: SYSTEM_TUN_OUTBOUNDS_INTERFACE),
            "autoSystemWfpBlockLeak" to Json.strings(SYSTEM_TUN_BLOCK_LEAK),
        )

        /** Как выбирать физический интерфейс для сокетов ядра, если платформа не назвала его (D-102): по маршрутам системы. */
        const val SYSTEM_TUN_OUTBOUNDS_INTERFACE: String = "auto"

        /** Фильтры WFP: DNS только через TUN; версия IP без маршрутов в TUN — закрыта. */
        val SYSTEM_TUN_BLOCK_LEAK: List<String> = listOf("dns", "misconfigtun")

        private fun systemTunWithoutTun(): Diagnostic =
            Diagnostic.error(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "TUN ядра (D-97) — только в плане с TUN", "$.inbounds")

        /**
         * Локальный прокси (D-95, T11): SOCKS5 с паролем (и HTTP-прокси на том же
         * порту), только на `127.0.0.1`. UDP — для SOCKS5 UDP ASSOCIATE, тоже на
         * loopback.
         */
        fun localInbound(local: LocalProxySpec): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_LOCAL),
            "protocol" to Json.str("socks"),
            "listen" to Json.str(LocalProxySpec.ADDRESS),
            "port" to Json.num(local.port),
            "settings" to Json.obj(
                "auth" to Json.str("password"),
                "accounts" to Json.arr(listOf(Json.obj("user" to Json.str(local.user.reveal()), "pass" to Json.str(local.password.reveal())))),
                "udp" to Json.bool(true),
                "ip" to Json.str(LocalProxySpec.ADDRESS),
            ),
            "sniffing" to Json.obj(
                "enabled" to Json.bool(true),
                "destOverride" to Json.strings(listOf("http", "tls", "quic")),
                "routeOnly" to Json.bool(true),
            ),
        )

        private fun shareTags(share: ShareSpec): List<String> = share.endpoints.indices.map { XrayBackend.SHARE_TAG_PREFIX + it }

        /**
         * Источники, которым вход раздачи закрыт (D-51): адреса самого телефона
         * на интерфейсах раздачи, весь IPv4 вне подсетей раздачи и весь IPv6
         * (входы слушают только IPv4). Правила Xray не умеют «кроме», поэтому
         * «всё, кроме подсетей» — дополнение набором подсетей.
         */
        fun shareRefused(share: ShareSpec): List<Cidr> =
            share.endpoints.map { Cidr.of(it.address, it.address.bitLength) } +
                Cidr.complement(Cidr.ALL_V4, share.endpoints.map { it.subnet }) +
                Cidr.ALL_V6

        fun tunInbound(system: SystemTun? = null): JsonObject = Json.obj(
            "tag" to Json.str(XrayBackend.TAG_TUN_IN),
            "protocol" to Json.str("tun"),
            // Имя — всегда: без него Xray перебирает интерфейсы системы, а на Android это запрещено (XrayBackend.TUN_NAME).
            "settings" to if (system == null) {
                Json.obj("name" to Json.str(XrayBackend.TUN_NAME), "mtu" to Json.num(XrayBackend.TUN_MTU))
            } else {
                systemTunSettings(system)
            },
            "sniffing" to Json.obj(
                "enabled" to Json.bool(true),
                "destOverride" to Json.strings(listOf("http", "tls", "quic")),
                "routeOnly" to Json.bool(true),
            ),
        )
    }
}
