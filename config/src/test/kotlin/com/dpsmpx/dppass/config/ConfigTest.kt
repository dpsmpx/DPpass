package com.dpsmpx.dppass.config

import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.PortRange
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.routing.Conditions
import com.dpsmpx.dppass.routing.DomainMatcher
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.Rule
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

internal object Fixtures {
    private val root = File(System.getProperty("dppass.repoRoot") ?: "../")
    fun text(path: String): String = File(root, "tests/data/$path").readText()
}

class ConfigLoaderTest {
    private val loader = ConfigLoader()

    @Test
    fun validMultiLoads() {
        val r = loader.load(Fixtures.text("configs/valid-multi.json"))
        val ir = assertNotNull(r.valueOrNull()).ir
        assertEquals(6, ir.profiles.size)
        assertEquals(TransportClass.UDP_QUIC, ir.profiles.first { it.id.value == "hy2" }.transportClass)
        assertTrue(r.errors.isEmpty())
    }

    @Test
    fun errorsCarryPaths() {
        val r = loader.load(Fixtures.text("configs/invalid-reality-key.json"))
        assertTrue(r is Outcome.Failure)
        val d = r.errors.single()
        assertEquals(DiagCode.REALITY_PUBLIC_KEY_INVALID, d.code)
        assertEquals("$.profiles[0].security.public_key", d.path)
    }

    @Test
    fun limitsAreEnforcedBeforeParsing() {
        val small = ConfigLoader(ConfigLimits(maxBytes = 64))
        assertEquals(listOf(DiagCode.DOCUMENT_TOO_LARGE), small.load(Fixtures.text("configs/valid-minimal.json")).diagnostics.map { it.code })
        assertEquals(listOf(DiagCode.DOCUMENT_TOO_DEEP), loader.load("[".repeat(10_000)).diagnostics.map { it.code })
        assertEquals(listOf(DiagCode.DOCUMENT_EMPTY), loader.load("  \n").diagnostics.map { it.code })
    }

    @Test
    fun syntaxErrorDoesNotQuoteInput() {
        val r = loader.load("""{"format":"dppass.config","secret":"00000000-0000-4000-8000-000000000001" oops}""")
        assertEquals(DiagCode.JSON_SYNTAX, r.errors.single().code)
        assertFalse("00000000" in r.errors.single().message)
    }

    @Test
    fun unknownValuesAreErrorsNotGuesses() {
        val text = Fixtures.text("configs/valid-minimal.json").replace("\"fingerprint\": \"chrome\"", "\"fingerprint\": \"chrom\"")
        assertEquals(listOf(DiagCode.VALUE_UNKNOWN), loader.load(text).errors.map { it.code })
    }

    @Test
    fun foreignDocumentIsNotDppass() {
        assertEquals(DiagCode.FORMAT_NOT_DPPASS, loader.load("""{"outbounds":[]}""").errors.single().code)
    }
}

/**
 * Проверка профиля не зависит от того, откуда он пришёл (D-05): запись
 * подписки строится мимо `DocumentMapper`, поэтому имя сервера и `host`
 * проверяет и `ConfigValidator.validateProfile`.
 */
class ProfileValidationTest {
    private val reality = ConfigLoader().load(Fixtures.text("configs/valid-minimal.json")).valueOrNull()!!.ir.profiles.single()
    private val trojan = reality.copy(
        protocol = ProtocolSpec.Trojan(Secret("test-password-1")),
        security = SecuritySpec.Tls("t.example.org", emptyList(), null),
    )

    private fun codesAt(p: ServerProfile): List<Pair<DiagCode, String?>> =
        ConfigValidator.validateProfile(p, "profiles[0]").map { it.code to it.path }

    @Test
    fun validProfilesStayValid() {
        assertEquals(emptyList(), codesAt(reality))
        assertEquals(emptyList(), codesAt(trojan))
        // Имя без server_name и имя в другом регистре — не ошибка: регистр смысла не меняет.
        assertEquals(emptyList(), codesAt(trojan.copy(security = SecuritySpec.Tls(null, emptyList(), null))))
        assertEquals(emptyList(), codesAt(trojan.copy(security = SecuritySpec.Tls("T.Example.ORG", emptyList(), null))))
    }

    @Test
    fun serverNameIsChecked() {
        val badTls = trojan.copy(security = SecuritySpec.Tls("bad name.example.org", emptyList(), null))
        assertEquals(listOf(DiagCode.SERVER_NAME_INVALID to "profiles[0].security.server_name"), codesAt(badTls))
        val badReality = reality.copy(security = (reality.security as SecuritySpec.Reality).copy(serverName = "bad_name.example.com"))
        assertEquals(listOf(DiagCode.SERVER_NAME_INVALID to "profiles[0].security.server_name"), codesAt(badReality))
    }

    @Test
    fun transportHostIsChecked() {
        val hosts = listOf(
            TransportSpec.WebSocket("/ws", "bad host.example.org"),
            TransportSpec.HttpUpgrade("/u", "-bad-.example.net"),
            TransportSpec.XHttp("/x", "1.2.3", XHttpMode.AUTO),
        )
        for (t in hosts) {
            assertEquals(listOf(DiagCode.DOMAIN_INVALID to "profiles[0].transport.host"), codesAt(trojan.copy(transport = t)), t.toString())
        }
        assertEquals(emptyList(), codesAt(trojan.copy(transport = TransportSpec.WebSocket("/ws", null))))
    }

    @Test
    fun transportPathAndServiceNameAreChecked() {
        val paths = listOf(
            TransportSpec.WebSocket("ws", null),
            TransportSpec.HttpUpgrade("/a b", null),
            TransportSpec.XHttp("/x\u0001", null, XHttpMode.AUTO),
            TransportSpec.WebSocket("/" + "p".repeat(1024), null),
        )
        for (t in paths) {
            assertEquals(listOf(DiagCode.PATH_INVALID to "profiles[0].transport.path"), codesAt(trojan.copy(transport = t)), t.toString())
        }
        for (name in listOf("", "bad name", "s".repeat(257))) {
            assertEquals(
                listOf(DiagCode.PATH_INVALID to "profiles[0].transport.service_name"),
                codesAt(trojan.copy(transport = TransportSpec.Grpc(name))),
                name,
            )
        }
        assertEquals(emptyList(), codesAt(trojan.copy(transport = TransportSpec.Grpc("dppass.Tunnel"))))
        assertEquals(emptyList(), codesAt(trojan.copy(transport = TransportSpec.XHttp("/x?ed=2048", null, XHttpMode.AUTO))))
    }

    // D-55: устройство раздачи — SOCKS с паролем, только на частный IPv4 своей сети:
    // логин, пароль и трафик идут открыто, в интернет такой профиль не пускается.
    @Test
    fun relayDeviceIsOnlyPrivateIpv4WithPasswordOverPlainTcp() {
        val relay = reality.copy(
            endpoint = Endpoint(Host.Ip(IpAddress.parse("192.168.43.1")!!), 41234),
            protocol = ProtocolSpec.Socks(Secret("u-test"), Secret("p-test")),
            transport = TransportSpec.Tcp,
            security = SecuritySpec.None,
        )
        assertEquals(emptyList(), codesAt(relay))
        assertEquals(TransportClass.LOCAL_RELAY, relay.transportClass)
        for (host in listOf(Host.Ip(IpAddress.parse("203.0.113.10")!!), Host.Ip(IpAddress.parse("fd00::1")!!), Host.Domain("relay.example.org"))) {
            assertEquals(
                listOf(DiagCode.RELAY_ADDRESS_NOT_LOCAL to "profiles[0].server"),
                codesAt(relay.copy(endpoint = Endpoint(host, 41234))),
                host.toString(),
            )
        }
        assertEquals(
            listOf(DiagCode.TRANSPORT_PROTOCOL_MISMATCH to "profiles[0].security"),
            codesAt(relay.copy(security = SecuritySpec.Tls("t.example.org", emptyList(), null))),
        )
        assertEquals(
            listOf(DiagCode.TRANSPORT_PROTOCOL_MISMATCH to "profiles[0].transport"),
            codesAt(relay.copy(transport = TransportSpec.WebSocket("/ws", null))),
        )
        assertEquals(
            listOf(DiagCode.PASSWORD_EMPTY to "profiles[0].protocol.password"),
            codesAt(relay.copy(protocol = ProtocolSpec.Socks(Secret("u-test"), Secret("")))),
        )
    }

    // Документ устройство раздачи не несёт (D-55): протокола socks в формате нет.
    @Test
    fun documentCannotCarryRelayDevice() {
        val text = Fixtures.text("configs/valid-minimal.json")
            .replace(Regex("""\"protocol\"\s*:\s*\{[^}]*}"""), """"protocol": {"type": "socks", "user": "u", "password": "p"}""")
        val r = ConfigLoader().load(text)
        assertTrue(r is Outcome.Failure && r.errors.any { it.code == DiagCode.VALUE_UNKNOWN }, r.diagnostics.map { it.render() }.toString())
    }
}

class MigrationTest {
    private fun doc(version: Int) = Json.obj("format" to Json.str("dppass.config"), "format_version" to Json.num(version))

    @Test
    fun newerVersionIsRejectedAndInputUntouched() {
        val input = doc(7)
        val r = Migrator(currentVersion = 1).toCurrent(input)
        assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, r.errors.single().code)
        assertEquals(doc(7), input)
    }

    @Test
    fun chainAppliesExplicitSteps() {
        val step = ConfigMigration { d ->
            val m = LinkedHashMap(d.fields)
            m["format_version"] = JsonNumber("2")
            m["migrated"] = JsonString("yes")
            Outcome.Success(JsonObject(m))
        }
        val r = Migrator(currentVersion = 2, migrations = mapOf(1 to step)).toCurrent(doc(1))
        val out = assertNotNull(r.valueOrNull())
        assertEquals(1, out.fromVersion)
        assertEquals(JsonString("yes"), out.document["migrated"])
        assertTrue(r.diagnostics.any { it.code == DiagCode.MIGRATION_APPLIED })
    }

    @Test
    fun missingStepIsUnsupportedNotDefaulted() {
        val r = Migrator(currentVersion = 3, migrations = emptyMap()).toCurrent(doc(1))
        assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, r.errors.single().code)
    }

    @Test
    fun failedStepReportsCauseAndKeepsOriginal() {
        val input = doc(1)
        val failing = ConfigMigration { Outcome.failure(DiagCode.FIELD_MISSING, "нет поля x") }
        val r = Migrator(currentVersion = 2, migrations = mapOf(1 to failing)).toCurrent(input)
        val e = r.errors.single()
        assertEquals(DiagCode.MIGRATION_FAILED, e.code)
        assertEquals(DiagCode.FIELD_MISSING, e.causes.single().code)
        assertEquals(doc(1), input)
    }
}

class WriterAndNormalizerTest {
    private val loader = ConfigLoader()

    @Test
    fun fullExportRoundTrips() {
        val ir = loader.load(Fixtures.text("configs/valid-multi.json")).valueOrNull()!!.ir
        val again = loader.load(ConfigWriter.write(ir, ConfigWriter.Mode.FULL)).valueOrNull()!!.ir
        assertEquals(ir, again)
    }

    @Test
    fun automaticDomesticRoundTrips() {
        // D-45: поле читается и пишется; по умолчанию выключено — документ значит
        // ровно то, что в нём написано (D-05).
        val base = loader.load(Fixtures.text("configs/valid-multi.json")).valueOrNull()!!.ir
        assertFalse(base.routing.automaticDomestic, "по умолчанию выключено")
        val on = base.copy(routing = base.routing.copy(automaticDomestic = true))
        val again = loader.load(ConfigWriter.write(on, ConfigWriter.Mode.FULL)).valueOrNull()!!.ir
        assertTrue(again.routing.automaticDomestic)
        assertEquals(on, again)
    }

    @Test
    fun redactedExportHasNoSecretsAndCannotActivate() {
        val text = Fixtures.text("configs/valid-multi.json")
        val ir = loader.load(text).valueOrNull()!!.ir
        val exported = ConfigWriter.write(ir)
        for (secret in listOf("00000000-0000-4000-8000-000000000001", "test-password-1", "test-password-2", "01234567")) {
            assertFalse(secret in exported, "в экспорте осталось $secret")
        }
        assertTrue(loader.load(exported).errors.isNotEmpty())
    }

    @Test
    fun normalizationIsIdempotentAndKeepsRuleOrder() {
        val text = Fixtures.text("configs/valid-multi.json")
            .replace(Regex("\"domain_suffix\": \\[\\s*\"example\\.ru\"\\s*]"), "\"domain_suffix\": [\"example.ru\", \"EXAMPLE.ru\"]")
        assertTrue("EXAMPLE.ru" in text, "замена в фикстуре не сработала")
        val r = loader.load(text)
        val ir = r.valueOrNull()!!.ir
        assertTrue(r.diagnostics.any { it.code == DiagCode.RULE_VALUE_DUPLICATE })
        val once = Normalizer.normalize(ir)
        assertEquals(ir, once.ir)
        assertTrue(once.notes.isEmpty())
        assertEquals(listOf("bank-app-direct", "ads-block", "ru-direct", "ru-ip-direct", "quic-block"), ir.routing.rules.map { it.id.value })
    }
}

/** Формат 3 (D-107): параметры QUIC и перескок портов Hysteria2. */
class ConfigFormatV3Test {
    private val loader = ConfigLoader()

    @Test
    fun quicAndHopRoundTripAndOlderVersionsMigrate() {
        val r = loader.load(Fixtures.text("configs/valid-format-v3.json"))
        val ir = assertNotNull(r.valueOrNull(), r.diagnostics.map { it.render() }.toString()).ir
        val hy = ir.profiles.first { it.id.value == "hy2-brutal-hop" }.protocol as ProtocolSpec.Hysteria2
        assertEquals(Hysteria2Congestion.BRUTAL, hy.congestion)
        assertEquals(
            Hysteria2Quic(
                bbrProfile = BbrProfile.AGGRESSIVE, brutalUp = 13_107_200, brutalDown = 6_553_600, initStreamReceiveWindow = 8_388_608,
                maxStreamReceiveWindow = 8_388_608, initConnReceiveWindow = 20_971_520, maxConnReceiveWindow = 20_971_520,
                maxIdleTimeoutSecs = 30, keepAlivePeriodSecs = 10, disablePathMtuDiscovery = true,
            ),
            hy.quic,
        )
        val ports = listOf(PortRange(20000, 20010), PortRange(8443, 8443))
        assertEquals(Hysteria2Hop(setOf(HopMode.INTERVAL_REMOTE, HopMode.PER_CONN_REMOTE), ports, CountRange(10, 30)), hy.hop)
        val written = ConfigWriter.write(ir, ConfigWriter.Mode.FULL)
        assertEquals(ir, loader.load(written).valueOrNull()!!.ir, "туда и обратно — тот же IR")
        // Документ версии 2 — через миграцию 2 → 3, без потерь.
        val v2 = loader.load(Fixtures.text("configs/valid-format-v2.json"))
        assertTrue(v2.diagnostics.any { it.code == DiagCode.MIGRATION_APPLIED }, v2.diagnostics.map { it.render() }.toString())
    }

    @Test
    fun coreLimitsAreRejectedWithPaths() {
        val r = loader.load(Fixtures.text("configs/invalid-format-v3-limits.json"))
        val at = r.errors.map { it.code to it.path }
        val p = "$.profiles[0].protocol"
        assertEquals(
            setOf(
                DiagCode.TRANSPORT_SETTING_INVALID to "$p.congestion",
                DiagCode.TRANSPORT_SETTING_INVALID to "$p.quic.brutal_down",
                DiagCode.TRANSPORT_SETTING_INVALID to "$p.quic.max_idle_timeout",
                DiagCode.TRANSPORT_SETTING_INVALID to "$p.hop.interval",
            ),
            at.toSet(),
        )
        fun codesAt(text: String) = loader.load(text).errors.map { it.code to it.path }
        val base = Fixtures.text("configs/valid-format-v3.json")
        assertEquals(
            listOf(DiagCode.VALUE_UNKNOWN to "$.profiles[0].protocol.hop.modes[0]"),
            codesAt(base.replace("\"interval_remote\", \"per_conn_remote\"", "\"sometimes\"")),
        )
        assertEquals(
            listOf(DiagCode.TRANSPORT_SETTING_INVALID to "$.profiles[0].protocol.hop.ports[0]"),
            codesAt(base.replace("\"20000-20010\"", "\"0-5\"")),
        )
        assertEquals(
            listOf(DiagCode.TRANSPORT_SETTING_INVALID to "$.profiles[0].protocol.quic.brutal_up"),
            codesAt(base.replace("\"brutal_up\": 13107200", "\"brutal_up\": ${Long.MAX_VALUE}")),
            "скорость в битах (×8) не переполняет Long",
        )
        assertEquals(
            listOf(DiagCode.FIELD_UNKNOWN to "$.profiles[0].protocol.quic.debug"),
            codesAt(base.replace("\"bbr_profile\": \"aggressive\",", "\"bbr_profile\": \"aggressive\", \"debug\": true,")),
        )
    }
}

/** Формат 2 (D-37): новые значения и поля, миграция 1 → 2. */
class ConfigFormatV2Test {
    private val loader = ConfigLoader()

    @Test
    fun newValuesAndFieldsRoundTrip() {
        val r = loader.load(Fixtures.text("configs/valid-format-v2.json"))
        val ir = assertNotNull(r.valueOrNull()).ir
        fun profile(id: String) = ir.profiles.first { it.id.value == id }
        assertEquals(TlsFingerprint.QQ, (profile("reality-qq").security as SecuritySpec.Reality).fingerprint)
        assertEquals(TlsFingerprint.EDGE, (profile("ws-edge").security as SecuritySpec.Tls).fingerprint)
        assertEquals(TlsFingerprint.IOS, (profile("trojan-ios").security as SecuritySpec.Tls).fingerprint)
        assertEquals(Hysteria2Congestion.BBR, (profile("hy2-bbr").protocol as ProtocolSpec.Hysteria2).congestion)
        val extra = (profile("xhttp-extra").transport as TransportSpec.XHttp).extra
        assertEquals(CountRange(100, 1000), extra.xPaddingBytes)
        assertEquals(CountRange(1_000_000, 1_000_000), extra.scMaxEachPostBytes)
        assertTrue(extra.noGrpcHeader)
        assertEquals(Xmux(CountRange(16, 32), null, CountRange(64, 128), CountRange(600, 900), CountRange(1800, 3000), 30), extra.xmux)

        val written = ConfigWriter.write(ir, ConfigWriter.Mode.FULL)
        val version = ConfigFormat.CURRENT_VERSION
        assertTrue("\"format_version\": $version" in written || "\"format_version\":$version" in written, "пишется текущая версия")
        assertEquals(ir, loader.load(written).valueOrNull()!!.ir)
    }

    @Test
    fun version1IsMigratedNotRejected() {
        val r = loader.load(Fixtures.text("configs/valid-minimal.json"))
        val loaded = assertNotNull(r.valueOrNull())
        assertEquals(1, loaded.sourceVersion)
        assertTrue(r.diagnostics.any { it.code == DiagCode.MIGRATION_APPLIED })
        assertTrue(r.errors.isEmpty())
    }

    @Test
    fun badRangesAndConflictingXmuxAreRejectedWithPaths() {
        val base = Fixtures.text("configs/valid-format-v2.json")
        fun codesAt(text: String) = loader.load(text).errors.map { it.code to it.path }
        assertEquals(
            listOf(DiagCode.TRANSPORT_SETTING_INVALID to "$.profiles[2].transport.x_padding_bytes"),
            codesAt(base.replace("\"x_padding_bytes\": \"100-1000\"", "\"x_padding_bytes\": \"1000-100\"")),
        )
        assertEquals(
            listOf(DiagCode.TRANSPORT_SETTING_INVALID to "$.profiles[2].transport.x_padding_bytes"),
            codesAt(base.replace("\"x_padding_bytes\": \"100-1000\"", "\"x_padding_bytes\": \"0-1000\"")),
        )
        assertEquals(
            listOf(DiagCode.TRANSPORT_SETTING_INVALID to "$.profiles[2].transport.xmux.max_connections"),
            codesAt(base.replace("\"max_concurrency\": \"16-32\",", "\"max_concurrency\": \"16-32\", \"max_connections\": 4,")),
        )
        assertEquals(
            listOf(DiagCode.VALUE_UNKNOWN to "$.profiles[3].protocol.congestion"),
            // brutal с формата 3 (D-107) — значение ядра; незнакомое — по-прежнему отказ.
            codesAt(base.replace("\"congestion\": \"bbr\"", "\"congestion\": \"cubic\"")),
        )
        // «0» — то же, что поля нет: так понимает Xray.
        val zero = loader.load(base.replace("\"sc_min_posts_interval_ms\": \"10-50\"", "\"sc_min_posts_interval_ms\": 0")).valueOrNull()!!.ir
        assertEquals(null, (zero.profiles[2].transport as TransportSpec.XHttp).extra.scMinPostsIntervalMs)
    }
}

/**
 * Пределы документа (docs/PERFORMANCE_BUDGET.md, §2): ровно на пределе —
 * принимается, на один больше — `LIMIT_EXCEEDED` с путём. Регрессия в
 * сравнении (`>=` вместо `>`, снятая проверка) так не пройдёт молча.
 */
class ConfigLimitsTest {
    private val limits = ConfigLimits()
    private val base = assertNotNull(ConfigLoader().load(Fixtures.text("configs/valid-minimal.json")).valueOrNull()).ir

    private fun limitPaths(ir: ConfigIr) = ConfigValidator.validate(ir, limits).filter { it.code == DiagCode.LIMIT_EXCEEDED }.map { it.path }

    @Test
    fun profilesUpToLimitPassOneMoreIsRejected() {
        val p = base.profiles.first()
        fun many(n: Int) = base.copy(profiles = (1..n).map { p.copy(id = ProfileId("p$it")) })
        assertEquals(512, limits.maxProfiles, "как в PERFORMANCE_BUDGET §2")
        assertEquals(emptyList(), limitPaths(many(limits.maxProfiles)))
        assertEquals(listOf("$.profiles"), limitPaths(many(limits.maxProfiles + 1)))
    }

    @Test
    fun ruleValuesUpToLimitPassOneMoreIsRejected() {
        fun rules(values: Int): ConfigIr {
            // Значения поровну в правилах, не больше предела числа правил.
            val perRule = values / 100
            val list = (0 until 100).map { r ->
                val n = if (r == 99) values - perRule * 99 else perRule
                Rule(RuleId("r$r"), Conditions(domains = (0 until n).map { DomainMatcher.Full("h$r-$it.example.com") }), RouteAction.DIRECT)
            }
            return base.copy(routing = base.routing.copy(rules = list))
        }
        assertEquals(100_000, limits.maxRuleValues, "как в PERFORMANCE_BUDGET §2")
        assertEquals(emptyList(), limitPaths(rules(limits.maxRuleValues)))
        assertEquals(listOf("$.routing.rules"), limitPaths(rules(limits.maxRuleValues + 1)))
    }
}
