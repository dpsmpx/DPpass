package com.dpsmpx.dppass.engine.mock

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ProtocolKind
import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecurityKind
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.TransportKind
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.config.VlessFlow
import com.dpsmpx.dppass.core.Checksums
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonParseException
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.EngineFeature
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.routing.AppLowering
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.routing.DomainMatcher

/**
 * Фиктивное ядро: доказывает абстракцию без настоящей сети.
 *
 * Два набора возможностей — [FULL] (всё, что есть в IR v1) и
 * [LIMITED] (без XHTTP, Hysteria2, DoT, правил с приложениями) — это
 * «второй бэкенд» в тестах: одна и та же конфигурация проходит через
 * разные матрицы, и отказ неподдержанного виден с путём.
 */
object MockBackend {
    val FULL: EngineCapabilities = EngineCapabilities(
        backendId = "mock",
        backendVersion = "1",
        protocols = ProtocolKind.entries.toSet(),
        transports = TransportKind.entries.toSet(),
        securities = SecurityKind.entries.toSet(),
        flows = VlessFlow.entries.toSet(),
        features = EngineFeature.entries.toSet(),
    )

    val LIMITED: EngineCapabilities = EngineCapabilities(
        backendId = "mock-limited",
        backendVersion = "1",
        protocols = setOf(ProtocolKind.VLESS, ProtocolKind.TROJAN, ProtocolKind.SHADOWSOCKS),
        transports = setOf(TransportKind.TCP, TransportKind.WEBSOCKET, TransportKind.GRPC),
        securities = setOf(SecurityKind.NONE, SecurityKind.TLS, SecurityKind.REALITY),
        flows = setOf(VlessFlow.NONE, VlessFlow.VISION),
        features = setOf(EngineFeature.DNS_DOH, EngineFeature.GEOSITE, EngineFeature.GEOIP, EngineFeature.TUN_FD),
    )
}

class MockBackendCompiler(override val capabilities: EngineCapabilities = MockBackend.FULL) : BackendCompiler {
    override fun compile(ir: ConfigIr, plan: CompilePlan): Outcome<CompiledConfig> {
        val problems = CapabilityChecker.check(ir, capabilities, plan)
        if (problems.any { it.isError }) return Outcome.Failure(problems)
        val profile = ir.profile(plan.profileId)
            ?: return Outcome.failure(DiagCode.PROFILE_NOT_FOUND, "нет профиля «${plan.profileId}»")
        val lowered = AppLowering.lower(ir.routing)
        // Разбиение ClientHello (D-68) — как у настоящего ядра: без TLS
        // разбивать нечего, и это предупреждение, а не тишина (D-05).
        val split = plan.splitClientHello && profile.security != SecuritySpec.None
        val notSplit = Diagnostic.warning(DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED, "mock: у «${profile.name}» нет TLS — разбивать нечего")
            .takeIf { plan.splitClientHello && !split }

        val credential = when (val p = profile.protocol) {
            is ProtocolSpec.Vless -> p.id.reveal()
            is ProtocolSpec.Trojan -> p.password.reveal()
            is ProtocolSpec.Shadowsocks -> p.password.reveal()
            is ProtocolSpec.Hysteria2 -> p.password.reveal()
            is ProtocolSpec.Socks -> p.password.reveal()
        }
        val outbound = Json.obj(
            "protocol" to Json.str(profile.protocol.kind.name.lowercase()),
            "server" to Json.str(profile.endpoint.host.toString()),
            "port" to Json.num(profile.endpoint.port),
            "credential" to Json.str(credential),
            "transport" to Json.str(profile.transport.kind.name.lowercase()),
            "transport_path" to Json.str(transportPath(profile.transport)),
            "security" to Json.str(profile.security.kind.name.lowercase()),
            "server_name" to Json.str(serverName(profile.security)),
            "split_client_hello" to Json.bool(true).takeIf { split },
        )
        val routes = lowered.engineRules.map { rule ->
            val c = rule.conditions
            Json.obj(
                "id" to Json.str(rule.id.value),
                "action" to Json.str(rule.action.name.lowercase()),
                "domain" to Json.strings(c.domains.map(::domainText)),
                "ip" to Json.strings(c.ipCidrs.map { it.toString() } + c.geoIps.map { "geoip:$it" }),
                "geosite" to Json.strings(c.geoSites),
                "apps" to Json.strings(c.apps),
                "port" to Json.strings(c.ports.map { it.toString() }),
            )
        }
        val dns = Json.arr(
            ir.dns.servers.map { s ->
                Json.obj(
                    "id" to Json.str(s.id),
                    "transport" to Json.str(dnsTransport(s.transport)),
                    "route" to Json.str(s.route.name.lowercase()),
                )
            },
        )
        val doc = Json.obj(
            "backend" to Json.str(capabilities.backendId),
            "version" to Json.str(capabilities.backendVersion),
            "profile" to Json.str(profile.id.value),
            "tun" to Json.bool(plan.withTun),
            "outbound" to outbound,
            "default" to Json.str(ir.routing.defaultAction.name.lowercase()),
            "routes" to Json.arr(routes),
            "dns" to dns,
            "dns_default" to Json.str(ir.dns.defaultServerId),
        )
        val payload = Json.write(doc, pretty = false)
        val compiled = CompiledConfig(capabilities.backendId, capabilities.backendVersion, profile.id, payload, Checksums.sha256(payload))
        return Outcome.Success(compiled, problems + listOfNotNull(notSplit))
    }

    private fun domainText(m: DomainMatcher): String = when (m) {
        is DomainMatcher.Full -> "full:${m.name}"
        is DomainMatcher.Suffix -> "domain:${m.suffix}"
        is DomainMatcher.Keyword -> "keyword:${m.keyword}"
    }

    private fun transportPath(t: TransportSpec): String? = when (t) {
        is TransportSpec.WebSocket -> t.path
        is TransportSpec.HttpUpgrade -> t.path
        is TransportSpec.XHttp -> t.path
        is TransportSpec.Grpc -> t.serviceName
        TransportSpec.Tcp, TransportSpec.Native -> null
    }

    private fun serverName(s: SecuritySpec): String? = when (s) {
        is SecuritySpec.Tls -> s.serverName
        is SecuritySpec.Reality -> s.serverName
        SecuritySpec.None -> null
    }

    private fun dnsTransport(t: DnsTransport): String = when (t) {
        is DnsTransport.Udp -> "udp://${t.server}"
        is DnsTransport.Tcp -> "tcp://${t.server}"
        is DnsTransport.Https -> t.url
        is DnsTransport.Tls -> "tls://${t.server}"
        DnsTransport.System -> "system"
    }
}

/** Поведение фиктивного ядра в тестах: что сломать и где. */
data class MockBehavior(
    val rejectConfig: Boolean = false,
    val failStart: Boolean = false,
)

/**
 * Фиктивное ядро. Как и настоящее, одновременно держит одну сессию:
 * второй запуск без остановки — ошибка, а не тихая подмена.
 */
class MockProxyEngine(
    override val capabilities: EngineCapabilities = MockBackend.FULL,
    var behavior: MockBehavior = MockBehavior(),
) : ProxyEngine {
    private var current: MockSession? = null

    /** История запусков (идентификаторы профилей) — для тестов жизненного цикла. */
    val startedProfiles: MutableList<String> = mutableListOf()

    override suspend fun validate(config: CompiledConfig): Outcome<Unit> {
        if (config.backendId != capabilities.backendId) {
            return Outcome.failure(DiagCode.BACKEND_REJECTED_CONFIG, "конфигурация для ${config.backendId}, а ядро — ${capabilities.backendId}")
        }
        val doc = try {
            Json.parse(config.payloadForEngine()) as? JsonObject
        } catch (e: JsonParseException) {
            null
        } ?: return Outcome.failure(DiagCode.BACKEND_REJECTED_CONFIG, "ядро не разобрало конфигурацию")
        if ((doc["backend"] as? JsonString)?.value != capabilities.backendId) {
            return Outcome.failure(DiagCode.BACKEND_REJECTED_CONFIG, "чужой формат конфигурации")
        }
        if (behavior.rejectConfig) {
            return Outcome.Failure(
                listOf(
                    Diagnostic.error(DiagCode.BACKEND_REJECTED_CONFIG, "ядро отвергло конфигурацию")
                        .withCause(Diagnostic.error(DiagCode.INTERNAL_ERROR, "mock: rejected by behavior")),
                ),
            )
        }
        return Outcome.Success(Unit)
    }

    override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> {
        if (current?.state() == EngineState.RUNNING) {
            return Outcome.failure(DiagCode.BACKEND_ALREADY_RUNNING, "ядро уже запущено; сначала stop()")
        }
        if (tun != null && EngineFeature.TUN_FD !in capabilities.features) {
            return Outcome.failure(DiagCode.BACKEND_START_FAILED, "ядро не принимает fd TUN")
        }
        if (behavior.failStart) return Outcome.failure(DiagCode.BACKEND_START_FAILED, "mock: отказ запуска по сценарию")
        val session = MockSession(config)
        current = session
        startedProfiles += config.profileId.value
        return Outcome.Success(session)
    }

    fun runningSession(): EngineSession? = current?.takeIf { it.state() == EngineState.RUNNING }

    private class MockSession(override val compiled: CompiledConfig) : EngineSession {
        private var state = EngineState.RUNNING

        override fun state(): EngineState = state

        override fun stats(): TrafficStats = TrafficStats(0, 0)

        override suspend fun stop() {
            state = EngineState.STOPPED
        }
    }
}
