package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.capabilityDiff
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.routing.RouteAction
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

private const val UUID = "00000000-0000-4000-8000-000000000001"

private const val REALITY = """{"id": "r", "name": "R", "server": "203.0.113.10", "port": 443,
  "protocol": {"type": "vless", "id": "$UUID", "flow": "vision"},
  "transport": {"type": "tcp"},
  "security": {"type": "reality", "server_name": "www.example.com",
    "public_key": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8", "short_id": "01234567"}}"""

private const val DOH = """{"servers": [{"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query", "route": "tunnel"}],
  "default": "remote"}"""

/** Документ DPpass из частей: один профиль, маршрутизация, DNS. */
private fun ir(profile: String = REALITY, routing: String = "{}", dns: String = DOH): ConfigIr {
    val text = """{"format": "dppass.config", "format_version": 1, "profiles": [$profile], "routing": $routing, "dns": $dns}"""
    val r = ConfigLoader().load(text)
    return r.valueOrNull()?.ir ?: fail("документ теста не разобран: ${r.diagnostics.map { it.render() }}")
}

private fun corpus(name: String): ConfigIr =
    ConfigLoader().load(File(System.getProperty("dppass.repoRoot"), "tests/data/configs/$name").readText()).valueOrNull()!!.ir

private fun compile(ir: ConfigIr, withTun: Boolean = true, profile: Int = 0): Outcome<CompiledConfig> =
    XrayCompiler().compile(ir, CompilePlan(ir.profiles[profile].id, withTun))

private fun payload(ir: ConfigIr, withTun: Boolean = true, profile: Int = 0): JsonObject {
    val r = compile(ir, withTun, profile)
    val compiled = r.valueOrNull() ?: fail("не скомпилировано: ${r.diagnostics.map { it.render() }}")
    return Json.parse(compiled.payloadForEngine()) as JsonObject
}

/** Отказ: коды и пути ошибок (D-05 — путь обязателен). */
private fun errors(r: Outcome<*>): List<Pair<DiagCode, String?>> {
    assertTrue(r is Outcome.Failure, "ожидался отказ компиляции")
    return r.errors.map { it.code to it.path }
}

private operator fun JsonValue?.get(key: String): JsonValue? = (this as JsonObject)[key]
private val JsonValue?.items: List<JsonValue> get() = (this as JsonArray).items
private val JsonValue?.text: String get() = (this as JsonString).value
private val JsonValue?.int: Int? get() = (this as JsonNumber).toIntOrNull()

private fun rules(p: JsonObject): List<JsonValue> = p["routing"]["rules"].items
private fun ruleTags(p: JsonObject): List<String> = rules(p).map { it["ruleTag"].text }
private fun outbound(p: JsonObject, tag: String): JsonValue = p["outbounds"].items.single { it["tag"].text == tag }

/**
 * Компилятор IR → Xray 26.9.30 (D-24): смысл IR сохраняется или
 * компиляция отказывает с путём (D-05). Что ядро делает с результатом —
 * эталоны корпуса и шаг hostcheck «Xray» (`docs/TESTING.md`, «Эталоны Xray»);
 * здесь — решения самого компилятора.
 */
class XrayCompilerTest {
    @Test
    fun matrixLacksOnlyWhatXrayCannotExpress() {
        val diff = capabilityDiff(MockBackend.FULL, XrayBackend.CAPABILITIES)
        assertEquals(setOf("feature:DNS_DOT", "feature:APP_RULES_IN_ENGINE", "feature:NETWORK_CONDITION"), diff.removed)
        assertTrue(diff.added.isEmpty())
        assertEquals(XrayBackend.VERSION, XrayBackend.CAPABILITIES.backendVersion)
    }

    @Test
    fun compileIsDeterministicAndHidesPayload() {
        val a = compile(ir()).valueOrNull()!!
        val b = compile(ir()).valueOrNull()!!
        assertEquals(a.payloadForEngine(), b.payloadForEngine())
        assertEquals(a.checksum, b.checksum)
        assertEquals("xray" to XrayBackend.VERSION, a.backendId to a.backendVersion)
        assertTrue(UUID in a.payloadForEngine())
        assertFalse(UUID in a.toString())
    }

    @Test
    fun xrayLogIsOff() {
        // Журнал DPpass — только Logger с редактированием (D-11); журнал доступа Xray писал бы адреса.
        val log = payload(ir())["log"]
        assertEquals("none", log["loglevel"].text)
        assertEquals(Json.bool(false), log["dnsLog"])
    }

    @Test
    fun tunInboundIsNamedSoXrayDoesNotEnumerateInterfaces() {
        // Найдено на устройстве (Android 15): без имени Xray подбирает его через net.Interfaces(),
        // netlink приложениям запрещён — «failed to build inbound handler for protocol tun».
        val tun = payload(ir())["inbounds"].items.single()
        assertEquals(XrayBackend.TUN_NAME, tun["settings"]["name"].text)
        assertTrue(XrayBackend.TUN_NAME.length in 1..15, "IFNAMSIZ")
    }

    @Test
    fun proxyTrafficCountersAreOn() {
        // TrafficStats сессии — из счётчиков исходящего proxy; без них мост не запускает ядро (D-25).
        for (withTun in listOf(true, false)) {
            val p = payload(ir(), withTun)
            assertEquals(JsonObject(emptyMap()), p["stats"])
            assertEquals(Json.bool(true), p["policy"]["system"]["statsOutboundUplink"])
            assertEquals(Json.bool(true), p["policy"]["system"]["statsOutboundDownlink"])
        }
    }

    @Test
    fun defaultActionIsFirstOutbound() {
        for (action in RouteAction.entries) {
            val p = payload(ir(routing = """{"default": "${action.name.lowercase()}"}"""))
            assertEquals(XrayBackend.outboundTag(action), p["outbounds"].items.first()["tag"].text, "$action")
        }
    }

    @Test
    fun userRulesKeepOrderAndIdsAfterSystemRules() {
        val p = payload(
            ir(
                routing = """{"rules": [
                  {"id": "ads", "action": "block", "domain_suffix": ["ads.example.com"], "domain": ["exact.example.com"],
                   "domain_keyword": ["tracker"], "geosite": ["category-ads"]},
                  {"id": "net", "action": "direct", "ip_cidr": ["198.51.100.0/24"], "geoip": ["ru"],
                   "port": ["443", "8000-8080"], "protocol": ["tcp"]}]}""",
            ),
        )
        assertEquals(listOf("dppass:dns-hijack", "dppass:dns:remote", "ads", "net"), ruleTags(p))
        val (ads, net) = rules(p).takeLast(2)
        assertEquals(
            setOf("full:exact.example.com", "domain:ads.example.com", "keyword:tracker", "geosite:category-ads"),
            ads["domain"].items.map { it.text }.toSet(),
        )
        assertEquals("block", ads["outboundTag"].text)
        assertEquals(listOf("198.51.100.0/24", "geoip:ru"), net["ip"].items.map { it.text })
        assertEquals("443,8000-8080", net["port"].text)
        assertEquals("tcp", net["network"].text)
        assertEquals("direct", net["outboundTag"].text)
    }

    @Test
    fun leadingAppRulesStayInVpnService() {
        val p = payload(
            ir(
                routing = """{"rules": [
                  {"id": "bank", "action": "direct", "apps": ["com.example.bank"]},
                  {"id": "ads", "action": "block", "domain_suffix": ["ads.example.com"]}]}""",
            ),
        )
        assertFalse("bank" in ruleTags(p))
        assertTrue("ads" in ruleTags(p))
    }

    @Test
    fun appRuleAfterOtherRuleIsRejected() {
        val r = compile(
            ir(
                routing = """{"rules": [
                  {"id": "ads", "action": "block", "domain_suffix": ["ads.example.com"]},
                  {"id": "bank", "action": "direct", "apps": ["com.example.bank"]}]}""",
            ),
        )
        assertEquals(listOf(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.routing.rules"), errors(r))
    }

    @Test
    fun networkConditionIsRejectedWithPath() {
        val r = compile(ir(routing = """{"rules": [{"id": "m", "action": "direct", "network": ["mobile"]}]}"""))
        assertEquals(listOf(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.routing.rules[0].network"), errors(r))
    }

    @Test
    fun dnsOverTlsIsRejectedWithPath() {
        val r = compile(
            ir(
                dns = """{"servers": [{"id": "dot", "type": "tls", "address": "192.0.2.53:853", "server_name": "dns.example.net",
                  "route": "tunnel"}], "default": "dot"}""",
            ),
        )
        assertEquals(listOf(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.dns.servers[0]"), errors(r))
    }

    @Test
    fun dnsRulesFirstMatchWinsWithoutFallback() {
        val p = payload(
            ir(
                dns = """{"servers": [
                  {"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query", "route": "tunnel"},
                  {"id": "local", "type": "system", "route": "direct"},
                  {"id": "domestic", "type": "udp", "address": "192.0.2.53", "route": "direct"}],
                  "default": "remote",
                  "rules": [{"domain_suffix": ["example.ru"], "server": "local"}, {"domain": ["www.example.org"], "server": "domestic"}]}""",
            ),
        )
        val dns = p["dns"]
        val servers = dns["servers"].items
        // По записи на правило в порядке правил, сервер по умолчанию — последним и единственным запасным.
        assertEquals(listOf("dns:local", "dns:domestic", "dns:remote"), servers.map { it["tag"].text })
        assertEquals(listOf("domain:example.ru"), servers[0]["domains"].items.map { it.text })
        assertEquals(listOf("full:www.example.org"), servers[1]["domains"].items.map { it.text })
        for (s in servers.take(2)) {
            assertEquals(Json.bool(true), s["skipFallback"])
            assertEquals(Json.bool(true), s["finalQuery"])
        }
        assertEquals(null, servers[2]["skipFallback"])
        assertEquals(null, servers[2]["domains"])
        assertEquals(Json.bool(true), servers[2]["finalQuery"])
        assertEquals(Json.bool(true), dns["disableFallbackIfMatch"])
        assertEquals("localhost", servers[0]["address"].text)
        assertEquals("192.0.2.53" to 53, servers[1]["address"].text to servers[1]["port"].int)
    }

    @Test
    fun dnsQueriesFollowTheirRouteBeforeUserRules() {
        val p = payload(
            ir(
                routing = """{"rules": [{"id": "all-direct", "action": "direct", "ip_cidr": ["0.0.0.0/0"]}]}""",
                dns = """{"servers": [
                  {"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query", "route": "tunnel"},
                  {"id": "remote-tcp", "type": "tcp", "address": "dns.example.net:53", "route": "tunnel"},
                  {"id": "doh-direct", "type": "https", "url": "https://dns.example.org/dns-query", "route": "direct"},
                  {"id": "tcp-direct", "type": "tcp", "address": "192.0.2.54", "route": "direct"},
                  {"id": "udp-direct", "type": "udp", "address": "192.0.2.53", "route": "direct"}],
                  "default": "remote",
                  "rules": [
                    {"domain_suffix": ["a.example.com"], "server": "remote-tcp"},
                    {"domain_suffix": ["b.example.com"], "server": "doh-direct"},
                    {"domain_suffix": ["c.example.com"], "server": "tcp-direct"},
                    {"domain_suffix": ["d.example.com"], "server": "udp-direct"}]}""",
            ),
        )
        val addresses = p["dns"]["servers"].items.associate { it["tag"].text to it["address"].text }
        assertEquals("tcp://dns.example.net:53", addresses["dns:remote-tcp"])
        // Мимо диспетчера ядра (+local): маршрутизация их не видит, правила им не нужны.
        assertEquals("https+local://dns.example.org/dns-query", addresses["dns:doh-direct"])
        assertEquals("tcp+local://192.0.2.54:53", addresses["dns:tcp-direct"])
        // Через диспетчер — правило по тегу сервера раньше правил пользователя: «всё напрямую»
        // не уводит запросы туннельного DNS мимо туннеля (T4).
        assertEquals(
            listOf("dppass:dns-hijack", "dppass:dns:remote", "dppass:dns:remote-tcp", "dppass:dns:udp-direct", "all-direct"),
            ruleTags(p),
        )
        val byTag = rules(p).associateBy { it["ruleTag"].text }
        assertEquals("proxy", byTag["dppass:dns:remote"]["outboundTag"].text)
        assertEquals("proxy", byTag["dppass:dns:remote-tcp"]["outboundTag"].text)
        assertEquals("direct", byTag["dppass:dns:udp-direct"]["outboundTag"].text)
        assertEquals(listOf("dns:udp-direct"), byTag["dppass:dns:udp-direct"]["inboundTag"].items.map { it.text })
    }

    @Test
    fun udpDnsDirectByNameIsRejected() {
        val r = compile(
            ir(
                dns = """{"servers": [
                  {"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query", "route": "tunnel"},
                  {"id": "domestic", "type": "udp", "address": "dns.example.ru", "route": "direct"}],
                  "default": "remote", "rules": [{"domain_suffix": ["example.ru"], "server": "domestic"}]}""",
            ),
        )
        assertEquals(listOf(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.dns.servers[1]"), errors(r))
    }

    @Test
    fun hysteria2TlsOptionsXrayWouldIgnoreAreRejected() {
        val r = compile(
            ir(
                profile = """{"id": "hy2", "name": "H", "server": "192.0.2.30", "port": 8443,
                  "protocol": {"type": "hysteria2", "password": "test-password-2"}, "transport": {"type": "native"},
                  "security": {"type": "tls", "server_name": "hy2.example.com", "alpn": ["h2"], "fingerprint": "chrome"}}""",
            ),
        )
        assertEquals(
            setOf(
                DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.profiles[0].security.alpn",
                DiagCode.CAPABILITY_FEATURE_UNSUPPORTED to "$.profiles[0].security.fingerprint",
            ),
            errors(r).toSet(),
        )
    }

    @Test
    fun hysteria2ShortObfsPasswordIsRejected() {
        val r = compile(
            ir(
                profile = """{"id": "hy2", "name": "H", "server": "192.0.2.30", "port": 8443,
                  "protocol": {"type": "hysteria2", "password": "test-password-2", "obfs_password": "abc"},
                  "transport": {"type": "native"}, "security": {"type": "tls", "server_name": "hy2.example.com"}}""",
            ),
        )
        assertEquals(listOf(DiagCode.PASSWORD_FORMAT_INVALID to "$.profiles[0].protocol.obfs_password"), errors(r))
    }

    @Test
    fun hysteria2CompilesToHysteriaTransportWithSalamander() {
        val p = payload(corpus("valid-multi.json"), profile = 3)
        val proxy = outbound(p, "proxy")
        assertEquals("hysteria", proxy["protocol"].text)
        assertEquals(2, proxy["settings"]["version"].int)
        val stream = proxy["streamSettings"]
        assertEquals("hysteria", stream["network"].text)
        assertEquals("test-password-2", stream["hysteriaSettings"]["auth"].text)
        assertEquals("salamander", stream["finalmask"]["udp"].items.single()["type"].text)
    }

    // D-55: устройство раздачи — исходящий socks с паролем ко входу раздачи другого DPpass,
    // без надстроек транспорта (вход раздачи их не принимает, D-51).
    @Test
    fun relayDeviceCompilesToSocksWithPassword() {
        val base = ir()
        val relay = base.profiles.single().copy(
            id = ProfileId("relay.test"),
            name = "Устройство",
            endpoint = Endpoint(Host.Ip(IpAddress.parse("192.168.43.1")!!), 41234),
            protocol = ProtocolSpec.Socks(Secret("u-test"), Secret("p-test-0123456789")),
            transport = TransportSpec.Tcp,
            security = SecuritySpec.None,
        )
        val proxy = outbound(payload(base.copy(profiles = listOf(relay))), "proxy")
        assertEquals("socks", proxy["protocol"].text)
        assertEquals("192.168.43.1", proxy["settings"]["address"].text)
        assertEquals(41234, proxy["settings"]["port"].int)
        assertEquals("u-test", proxy["settings"]["user"].text)
        assertEquals("p-test-0123456789", proxy["settings"]["pass"].text)
        assertEquals("raw", proxy["streamSettings"]["network"].text)
        assertEquals("none", proxy["streamSettings"]["security"].text)
    }

    @Test
    fun shadowsocksKeyIsStandardBase64WithPadding() {
        // Xray читает ключ StdEncoding, а не сумев — молча берёт байты строки (D-05: только явно).
        val p = payload(
            ir(
                profile = """{"id": "ss", "name": "S", "server": "192.0.2.40", "port": 8388,
                  "protocol": {"type": "shadowsocks", "method": "2022-blake3-aes-128-gcm", "password": "AAECAwQFBgcICQoLDA0ODw"},
                  "transport": {"type": "tcp"}, "security": {"type": "none"}}""",
            ),
        )
        assertEquals("AAECAwQFBgcICQoLDA0ODw==", outbound(p, "proxy")["settings"]["password"].text)
    }

    @Test
    fun visionOutsideTcpTlsIsRejectedEvenPastTheValidator() {
        // Профиль мог прийти в IR мимо документа; компилятор не полагается на проверку разбора.
        val base = ir()
        val bad = base.copy(
            profiles = listOf(
                base.profiles[0].copy(
                    transport = TransportSpec.WebSocket("/ws", null),
                    security = SecuritySpec.Tls("www.example.com", emptyList(), null),
                ),
            ),
        )
        assertEquals(listOf(DiagCode.FLOW_REQUIRES_TCP_TLS to "$.profiles[0].protocol.flow"), errors(compile(bad)))
    }

    @Test
    fun domainResolutionIsOnePassFromTun() {
        val never = ir(routing = """{"domain_resolution": "never"}""")
        val ifNoMatch = ir(routing = """{"domain_resolution": "if_no_domain_match"}""")
        assertEquals("AsIs", payload(never)["routing"]["domainStrategy"].text)
        // Из TUN у соединения всегда есть адрес: повтор по IP Xray сделал бы с адресами своего DNS.
        assertEquals("AsIs", payload(ifNoMatch, withTun = true)["routing"]["domainStrategy"].text)
        assertEquals("IPIfNonMatch", payload(ifNoMatch, withTun = false)["routing"]["domainStrategy"].text)
    }

    @Test
    fun addressStrategyAnswersAppsAndGuidesDirect() {
        val expected = mapOf(
            "dual" to ("UseIP" to "ForceIP"),
            "prefer_ipv4" to ("UseIP" to "ForceIPv4v6"),
            "prefer_ipv6" to ("UseIP" to "ForceIPv6v4"),
            "ipv4_only" to ("UseIPv4" to "ForceIPv4"),
            "ipv6_only" to ("UseIPv6" to "ForceIPv6"),
        )
        for ((strategy, want) in expected) {
            val p = payload(
                ir(
                    dns = """{"servers": [{"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query",
                      "route": "tunnel"}], "default": "remote", "strategy": "$strategy"}""",
                ),
            )
            val direct = outbound(p, "direct")["streamSettings"]["sockopt"]["domainStrategy"].text
            assertEquals(want, p["dns"]["queryStrategy"].text to direct, strategy)
        }
    }

    @Test
    fun tunInboundAndDnsHijackOnlyWithTun() {
        val withTun = payload(ir(), withTun = true)
        val tun = withTun["inbounds"].items.single()
        assertEquals(XrayBackend.TAG_TUN_IN, tun["tag"].text)
        assertEquals("tun", tun["protocol"].text)
        assertEquals(XrayBackend.TUN_MTU, tun["settings"]["mtu"].int)
        // Имя из TLS/HTTP/QUIC — только для правил: соединение идёт на адрес, выбранный приложением.
        assertEquals(Json.bool(true), tun["sniffing"]["routeOnly"])
        val hijack = rules(withTun).first()
        assertEquals(listOf(XrayBackend.TUN_DNS4), hijack["ip"].items.map { it.text })
        assertEquals(XrayBackend.TAG_DNS_OUT, hijack["outboundTag"].text)
        assertEquals("dns", outbound(withTun, XrayBackend.TAG_DNS_OUT)["protocol"].text)

        val noTun = payload(ir(), withTun = false)
        assertTrue(noTun["inbounds"].items.isEmpty())
        assertFalse(noTun["outbounds"].items.any { it["tag"].text == XrayBackend.TAG_DNS_OUT })
        assertFalse("dppass:dns-hijack" in ruleTags(noTun))
    }

    @Test
    fun certificateCheckCannotBeDisabled() {
        val multi = corpus("valid-multi.json")
        for (i in multi.profiles.indices) {
            val text = compile(multi, profile = i).valueOrNull()!!.payloadForEngine()
            for (field in listOf("allowInsecure", "pinnedPeerCertSha256", "verifyPeerCertByName", "disableSystemRoot")) {
                assertFalse("\"$field\"" in text, "${multi.profiles[i].id}: $field (T5)")
            }
        }
    }

    @Test
    fun geoCodesAreCheckedAgainstTheInstalledSet() {
        // D-27: кода, атрибута или сочетания атрибутов нет в наборе геоданных ядра —
        // отказ с путём правила, а не условие, которое молча никогда не сработает (D-05).
        val set = GeodataManifest(
            "v0.0.0-20260101000000-0123456789ab", "0123456789ab", "2026-01", emptyList(), setOf("aa", "private"),
            mapOf(
                "example-a" to listOf(setOf("ads")),
                "example-plain" to emptyList(),
                "example-both" to listOf(setOf("ads", "cn")),
                // @ads и @cn есть, но у разных правил: @ads@cn ядро не выберет ни одного.
                "example-split" to listOf(setOf("ads"), setOf("cn")),
            ),
        )
        val routing = """{"rules": [
            {"id": "known", "action": "direct", "geoip": ["aa", "private"],
             "geosite": ["example-a", "example-a@ads", "example-plain", "example-both@cn@ads", "example-both@cn", "example-split@ads", "example-split@cn"]},
            {"id": "unknown-ip", "action": "direct", "geoip": ["zz"]},
            {"id": "unknown-site", "action": "block", "geosite": ["example-b"]},
            {"id": "unknown-attr", "action": "block", "geosite": ["example-a@cn"]},
            {"id": "split-attrs", "action": "block", "geosite": ["example-split@ads@cn"]}]}"""
        val dns = """{"servers": [{"id": "remote", "type": "https", "url": "https://dns.example.net/dns-query", "route": "tunnel"}],
            "default": "remote", "rules": [{"geosite": ["example-z"], "server": "remote"}]}"""
        val geo = ir(routing = routing, dns = dns)
        fun compileWith(codes: GeodataCodes) = XrayCompiler(geodata = codes).compile(geo, CompilePlan(geo.profiles[0].id, withTun = true))

        assertEquals(
            setOf(
                DiagCode.GEO_CODE_UNKNOWN to "$.routing.rules[1].geoip",
                DiagCode.GEO_CODE_UNKNOWN to "$.routing.rules[2].geosite",
                DiagCode.GEO_CODE_UNKNOWN to "$.routing.rules[3].geosite",
                DiagCode.GEO_CODE_UNKNOWN to "$.routing.rules[4].geosite",
                DiagCode.GEO_CODE_UNKNOWN to "$.dns.rules[0].geosite",
            ),
            errors(compileWith(GeodataCodes.Installed(set))).toSet(),
        )
        val split = compileWith(GeodataCodes.Installed(set)).diagnostics.single { it.path == "$.routing.rules[4].geosite" }
        assertTrue("нет правила со всеми атрибутами @ads@cn сразу" in split.message, split.message)
        val missing = errors(compileWith(GeodataCodes.Missing("в приложении нет набора")))
        assertTrue(missing.all { it.first == DiagCode.GEODATA_UNAVAILABLE }, "$missing")
        assertEquals(7, missing.size, "каждое условие geoip/geosite — с путём: $missing")
        assertTrue(compileWith(GeodataCodes.Unchecked).isSuccess, "без набора коды проверяет само ядро")
        val known = ir(routing = """{"rules": [{"id": "known", "action": "direct", "geoip": ["aa"], "geosite": ["example-a@ads"]}]}""")
        assertTrue(XrayCompiler(geodata = GeodataCodes.Installed(set)).compile(known, CompilePlan(known.profiles[0].id, true)).isSuccess)
    }

    /** D-51: раздача — вход SOCKS/HTTP с паролем только на адресах раздачи и только для клиентов раздачи. */
    @Test
    fun shareInboundsListenOnlyOnTetherAddressesWithAuth() {
        val gi = ir(routing = """{"rules": [{"id": "net", "action": "direct", "domain": ["net.example.com"]}]}""")
        val hotspot = ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24)
        val usb = ShareSpec.Endpoint(IpAddress.parse("192.168.42.129")!!, 24)
        val share = ShareSpec(listOf(hotspot, usb), 41234, Secret("u-test"), Secret("p-test-0123456789"))
        val p = Json.parse(XrayCompiler().compile(gi, CompilePlan(gi.profiles[0].id, true, share)).valueOrNull()!!.payloadForEngine()) as JsonObject
        val inbounds = p["inbounds"].items
        assertEquals(listOf("tun-in", "dppass:share-0", "dppass:share-1"), inbounds.map { it["tag"].text })
        for ((i, e) in share.endpoints.withIndex()) {
            val inb = inbounds[i + 1]
            assertEquals("socks", inb["protocol"].text)
            assertEquals(e.address.toString(), inb["listen"].text, "только адрес раздачи — не 0.0.0.0")
            assertEquals(41234, inb["port"].int)
            assertEquals("password", inb["settings"]["auth"].text)
            assertEquals("u-test", inb["settings"]["accounts"].items.single()["user"].text)
            assertEquals("p-test-0123456789", inb["settings"]["accounts"].items.single()["pass"].text)
        }
        // D-56: у сопряжённых устройств — свои входы рядом с основным.
        val paired = share.copy(guests = listOf(ShareSpec.Account(Secret("d-guest01"), Secret("p-guest-0123456789"))))
        val pp = Json.parse(XrayCompiler().compile(gi, CompilePlan(gi.profiles[0].id, true, paired)).valueOrNull()!!.payloadForEngine()) as JsonObject
        assertEquals(listOf("u-test", "d-guest01"), pp["inbounds"].items[1]["settings"]["accounts"].items.map { it["user"].text })
        // Первое правило: на вход раздачи — только клиенты из подсетей раздачи, не сам телефон.
        val first = rules(p).first()
        assertEquals("dppass:share-guard", first["ruleTag"].text)
        assertEquals(listOf("dppass:share-0", "dppass:share-1"), first["inboundTag"].items.map { it.text })
        assertEquals("block", first["outboundTag"].text)
        val refused = first["source"].items.map { Cidr.parse(it.text)!!.cidr }
        fun refused(ip: String) = refused.any { IpAddress.parse(ip)!! in it }
        assertFalse(refused("192.168.43.17"), "клиент точки доступа")
        assertFalse(refused("192.168.42.200"), "клиент USB-модема")
        assertTrue(refused("192.168.43.1"), "адрес самого телефона")
        assertTrue(refused("192.168.42.129"), "адрес самого телефона")
        assertTrue(refused("192.168.1.5"), "адрес телефона в домашнем Wi-Fi")
        assertTrue(refused("127.0.0.1"))
        assertTrue(refused("10.0.0.2"))
        assertTrue(refused("203.0.113.5"))
        assertTrue(refused("fd00::1"))
        // Правила пользователя действуют и для раздачи (правило без inboundTag).
        assertNull(rules(p).single { it["ruleTag"].text == "net" }["inboundTag"])
        // Без раздачи — ни входа, ни правила.
        val plain = payload(gi)
        assertEquals(listOf("tun-in"), plain["inbounds"].items.map { it["tag"].text })
        assertTrue(ruleTags(plain).none { it.startsWith("dppass:share") })
        // Адрес или подсеть не частные, подсеть без места для клиентов, порт ниже 1024 — раздачу не построить.
        assertFailsWith<IllegalArgumentException> { ShareSpec.Endpoint(IpAddress.parse("203.0.113.5")!!, 24) }
        assertFailsWith<IllegalArgumentException> { ShareSpec.Endpoint(IpAddress.parse("127.0.0.1")!!, 8) }
        assertFailsWith<IllegalArgumentException> { ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 8) }
        assertFailsWith<IllegalArgumentException> { ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 32) }
        assertFailsWith<IllegalArgumentException> { ShareSpec(listOf(hotspot), 80, Secret("u"), Secret("p")) }
        assertFailsWith<IllegalArgumentException> { ShareSpec(listOf(hotspot, hotspot), 41234, Secret("u"), Secret("p")) }
        // D-56: логин сопряжённого не повторяет другой — ядро держит входы по логину.
        assertFailsWith<IllegalArgumentException> {
            ShareSpec(listOf(hotspot), 41234, Secret("u"), Secret("p"), listOf(ShareSpec.Account(Secret("u"), Secret("q"))))
        }
    }

    /**
     * D-51, T11: «напрямую» для клиентов раздачи — свой исходящий, закрытый для
     * loopback телефона; правила те же, что у телефона. Без раздачи
     * конфигурация не меняется.
     */
    @Test
    fun shareDirectIsClosedToPhoneLoopback() {
        val routing = """{"default": "direct", "rules": [{"id": "net", "action": "direct", "domain": ["net.example.com"]}, """ +
            """{"id": "ads", "action": "block", "domain": ["ads.example.com"]}, {"id": "far", "action": "proxy", "domain": ["far.example.com"]}]}"""
        val gi = ir(routing = routing)
        val share = ShareSpec(listOf(ShareSpec.Endpoint(IpAddress.parse("192.168.43.1")!!, 24)), 41234, Secret("u-test"), Secret("p-test-0123456789"))
        val p = Json.parse(XrayCompiler().compile(gi, CompilePlan(gi.profiles[0].id, true, share)).valueOrNull()!!.payloadForEngine()) as JsonObject
        val outbounds = p["outbounds"].items
        val direct = outbounds.single { it["tag"].text == "direct" }
        val forShare = outbounds.single { it["tag"].text == XrayBackend.TAG_DIRECT_SHARE }
        assertEquals("freedom", forShare["protocol"].text)
        assertEquals(direct["streamSettings"], forShare["streamSettings"], "имя резолвится так же, как у direct (T4)")
        val closed = forShare["settings"]["finalRules"].items.single()
        assertEquals("block", closed["action"].text)
        assertEquals(listOf("127.0.0.0/8", "0.0.0.0/8", "::1/128", "::/128"), closed["ip"].items.map { it.text })
        assertNull(direct["settings"], "у direct телефона ограничений нет: DNS-сервер на 127.0.0.1 остаётся рабочим")
        // Перед правилом direct — его копия только для раздачи (свой ruleTag: Xray не
        // принимает повторов); block и proxy — общие.
        val r = rules(p)
        val net = r.indexOfFirst { it["ruleTag"].text == "dppass:share:net" }
        assertEquals(listOf("dppass:share-0"), r[net]["inboundTag"].items.map { it.text })
        assertEquals(XrayBackend.TAG_DIRECT_SHARE, r[net]["outboundTag"].text)
        assertEquals("net", r[net + 1]["ruleTag"].text)
        assertEquals(r[net]["domain"], r[net + 1]["domain"])
        assertNull(r[net + 1]["inboundTag"])
        assertEquals("direct", r[net + 1]["outboundTag"].text)
        assertEquals(ruleTags(p).size, ruleTags(p).toSet().size, "ruleTag не повторяются")
        assertEquals(1, r.count { it["ruleTag"].text == "ads" })
        assertEquals(1, r.count { it["ruleTag"].text == "far" })
        // Действие по умолчанию direct: раздаче — последним правилом свой исходящий.
        val last = r.last()
        assertEquals("dppass:share-default", last["ruleTag"].text)
        assertEquals(XrayBackend.TAG_DIRECT_SHARE, last["outboundTag"].text)
        // Без раздачи — ни исходящего, ни копий правил.
        val plain = payload(gi)
        assertTrue(plain["outbounds"].items.none { it["tag"].text == XrayBackend.TAG_DIRECT_SHARE })
        assertEquals(1, rules(plain).count { it["ruleTag"].text == "net" })
        assertTrue(ruleTags(plain).none { it == "dppass:share-default" })
        // По умолчанию proxy: правила для раздачи в конце нет — её клиентов ведёт первый исходящий.
        val viaProxy = ir(routing = """{"rules": [{"id": "net", "action": "direct", "domain": ["net.example.com"]}]}""")
        val pp = Json.parse(
            XrayCompiler().compile(viaProxy, CompilePlan(viaProxy.profiles[0].id, true, share)).valueOrNull()!!.payloadForEngine(),
        ) as JsonObject
        assertTrue(ruleTags(pp).none { it == "dppass:share-default" })
        assertEquals("proxy", pp["outbounds"].items.first()["tag"].text)
    }

    @Test
    fun automaticDomesticAddsCheckedRuRulesAfterUserRules() {
        // D-45: отечественное — напрямую, ПОСЛЕ правил пользователя, и
        // geosite/geoip — отдельными правилами (в одном Xray соединил бы их И).
        val routing = """{"rules": [{"id": "net", "action": "proxy", "domain": ["net.example.com"]}], "automatic_domestic": true}"""
        val gi = ir(routing = routing)
        // Коды ru сверяются с набором (D-27): нет в наборе — отказ с путём.
        val noRu = GeodataManifest("v0.0.0-20260101000000-0123456789ab", "0123456789ab", "2026-01", emptyList(), emptySet(), emptyMap())
        assertTrue(
            errors(XrayCompiler(geodata = GeodataCodes.Installed(noRu)).compile(gi, CompilePlan(gi.profiles[0].id, true)))
                .all { it.first == DiagCode.GEO_CODE_UNKNOWN },
            "кодов ru нет в наборе — GEO_CODE_UNKNOWN",
        )
        val withRu = GeodataManifest(
            "v0.0.0-20260101000000-0123456789ab",
            "0123456789ab",
            "2026-01",
            emptyList(),
            setOf("ru"),
            mapOf("category-ru" to emptyList()),
        )
        val p = Json.parse(
            XrayCompiler(geodata = GeodataCodes.Installed(withRu)).compile(gi, CompilePlan(gi.profiles[0].id, true)).valueOrNull()!!.payloadForEngine(),
        ) as JsonObject
        val tags = ruleTags(p)
        assertTrue(tags.indexOf("net") < tags.indexOf("dppass:auto-domestic-site"), "автосплит — после правил пользователя")
        assertEquals(listOf("dppass:auto-domestic-site", "dppass:auto-domestic-ip"), tags.filter { it.startsWith("dppass:auto-domestic") })
        val site = rules(p).single { it["ruleTag"].text == "dppass:auto-domestic-site" }
        val ip = rules(p).single { it["ruleTag"].text == "dppass:auto-domestic-ip" }
        assertEquals(listOf("geosite:category-ru"), site["domain"].items.map { it.text })
        assertNull(site["ip"], "site-правило без geoip: иначе Xray соединил бы через И (D-31)")
        assertEquals(listOf("geoip:ru"), ip["ip"].items.map { it.text })
        assertEquals("direct", site["outboundTag"].text)
        assertEquals("direct", ip["outboundTag"].text)
    }

    @Test
    fun serverNameIsLeftToTheSystemResolver() {
        // D-29: имя сервера ядро отдаёт системному dialer — система резолвит его вне
        // туннеля (пакет DPpass вне туннеля), а не DNS ядра, чьи серверы сами могут идти
        // через proxy. Поэтому у proxy нет sockopt: ни domainStrategy, ни dialerProxy.
        val multi = corpus("valid-multi.json")
        val byName = mutableListOf<String>()
        for (i in multi.profiles.indices) {
            val profile = multi.profiles[i]
            val proxy = outbound(payload(multi, profile = i), "proxy")
            assertEquals(profile.endpoint.host.toString(), proxy["settings"]["address"].text, profile.id.value)
            assertTrue(proxy["streamSettings"]["sockopt"] == null, "${profile.id}: sockopt у proxy (D-29)")
            if (profile.endpoint.host is Host.Domain) byName += profile.id.value
        }
        assertEquals(listOf("xhttp-cdn", "domestic-relay"), byName, "в корпусе есть серверы по имени")
    }

    @Test
    fun everyCorpusProfileCompiles() {
        val multi = corpus("valid-multi.json")
        for (i in multi.profiles.indices) {
            val r = compile(multi, profile = i)
            assertTrue(r.isSuccess && r.diagnostics.isEmpty(), "${multi.profiles[i].id}: ${r.diagnostics.map { it.render() }}")
        }
    }

    /** Формат 2 (D-37): отпечатки, настройки XHTTP прямо в xhttpSettings (не через extra), перегрузка Hysteria2. */
    @Test
    fun formatV2FieldsReachXray() {
        val v2 = corpus("valid-format-v2.json")
        fun proxy(id: String) = outbound(payload(v2, profile = v2.profiles.indexOfFirst { it.id.value == id }), "proxy")
        assertEquals("qq", proxy("reality-qq")["streamSettings"]["realitySettings"]["fingerprint"].text)
        assertEquals("edge", proxy("ws-edge")["streamSettings"]["tlsSettings"]["fingerprint"].text)

        val xhttp = proxy("xhttp-extra")["streamSettings"]["xhttpSettings"]
        assertEquals(null, xhttp["extra"], "extra заменил бы настройку целиком")
        assertEquals("100-1000", xhttp["xPaddingBytes"].text)
        assertEquals("1000000", xhttp["scMaxEachPostBytes"].text)
        assertEquals(Json.bool(true), xhttp["noGRPCHeader"])
        assertEquals("16-32", xhttp["xmux"]["maxConcurrency"].text)
        assertEquals(null, xhttp["xmux"]["maxConnections"])
        assertEquals(30, xhttp["xmux"]["hKeepAlivePeriod"].int)

        val hy2 = proxy("hy2-bbr")["streamSettings"]
        assertEquals("bbr", hy2["finalmask"]["quicParams"]["congestion"].text)
        assertEquals(null, hy2["finalmask"]["udp"], "без obfs — без Salamander")
        // Без congestion и obfs finalmask не пишется вовсе.
        val plain = ir(
            profile = """{"id": "h", "name": "H", "server": "192.0.2.30", "port": 8443, "protocol": {"type": "hysteria2", "password": "test-password-2"},
              "transport": {"type": "native"}, "security": {"type": "tls", "server_name": "hy2.example.com"}}""",
        )
        assertEquals(null, outbound(payload(plain), "proxy")["streamSettings"]["finalmask"])
    }
}
