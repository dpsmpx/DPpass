package com.dpsmpx.dppass.cli

import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ConfigWriter
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.SimulatedHealthChecker
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import com.dpsmpx.dppass.routing.NetworkKind
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.TransportProtocol
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionUpdater
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.system.exitProcess

/**
 * dppass-cli — оболочка DPpass на JVM. Делает то же, что приложение,
 * только без UI и с фиктивным ядром: так весь конвейер проверяется на
 * хосте (`smoke.cli` DP Verify, `tools/dpverify.toml`).
 *
 * Код выхода: 0 — успех; 1 — отказ по существу (ошибки диагностики);
 * 2 — неверный вызов.
 */
private const val USAGE = """dppass-cli <команда> [параметры]

  check <config.json> [--backend mock|mock-limited]
        разобрать, проверить, скомпилировать и активировать на фиктивном ядре
  route <config.json> (--domain D | --ip IP) [--port N] [--udp] [--app PKG] [--network wifi|mobile]
        решение маршрутизации с объяснением
  classify --condition NAME
        классификация сети на модели условия (NORMAL, ALLOWLIST_LIKE, …)
  plan <config.json> --condition NAME
        план кандидатов с причинами
  connect <config.json> --condition NAME
        подключение по плану на модели сети
  subscription <payload> [--headers headers.json] [--backend mock|mock-limited]
        обновление подписки из файла
  export <config.json>
        экспорт с отредактированными секретами
  report <config.json>
        локальный диагностический отчёт
  bench [--rules N]
        замер разбора, проверки, компиляции и решений маршрутизации"""

/** Версия в `User-Agent` запроса подписки (D-33); `cli` подписку по сети не загружает — тело берётся из файла. */
private const val CLI_VERSION = "cli"

fun main(args: Array<String>) {
    val code = try {
        run(args.toList())
    } catch (e: UsageError) {
        System.err.println(e.message)
        System.err.println()
        System.err.println(USAGE)
        2
    }
    exitProcess(code)
}

class UsageError(message: String) : Exception(message)

private class Args(list: List<String>) {
    val positional = mutableListOf<String>()
    val options = HashMap<String, String?>()

    init {
        var i = 0
        while (i < list.size) {
            val a = list[i]
            if (a.startsWith("--")) {
                val flagOnly = a in setOf("--udp")
                if (flagOnly) {
                    options[a] = null
                } else {
                    if (i + 1 >= list.size) throw UsageError("у $a нет значения")
                    options[a] = list[++i]
                }
            } else {
                positional += a
            }
            i++
        }
    }

    fun file(n: Int): File = File(positional.getOrNull(n) ?: throw UsageError("не указан файл")).also {
        if (!it.isFile) throw UsageError("нет файла $it")
    }

    fun opt(name: String): String? = options[name]
    fun has(name: String): Boolean = options.containsKey(name)
}

fun run(argv: List<String>): Int {
    if (argv.isEmpty()) throw UsageError("не указана команда")
    val a = Args(argv.drop(1))
    return when (argv[0]) {
        "check" -> check(a)
        "route" -> route(a)
        "classify" -> classify(a)
        "plan" -> plan(a)
        "connect" -> connect(a)
        "subscription" -> subscription(a)
        "export" -> export(a)
        "report" -> report(a)
        "bench" -> Bench.run(a.opt("--rules")?.toIntOrNull() ?: 2000)
        "help", "--help" -> {
            println(USAGE)
            0
        }
        else -> throw UsageError("неизвестная команда ${argv[0]}")
    }
}

private fun backend(name: String?): EngineCapabilities = when (name ?: "mock") {
    "mock" -> MockBackend.FULL
    "mock-limited" -> MockBackend.LIMITED
    else -> throw UsageError("неизвестный бэкенд $name (есть mock, mock-limited)")
}

private fun condition(a: Args): NetworkCondition {
    val name = a.opt("--condition") ?: throw UsageError("нужен --condition")
    return NetworkCondition.entries.firstOrNull { it.name == name.uppercase() }
        ?: throw UsageError("неизвестное условие $name; есть: ${NetworkCondition.entries.joinToString()}")
}

private fun core(caps: EngineCapabilities, clock: ManualClock = ManualClock(1_000_000)): DPpassCore = DPpassCore(
    compiler = MockBackendCompiler(caps),
    engine = MockProxyEngine(caps),
    store = InMemoryBlobStore(),
    clock = clock,
    selfPackage = "com.dpsmpx.dppass",
    platform = PlatformTraits(supportsExcludeRoute = true),
)

private fun printDiagnostics(ds: List<Diagnostic>, indent: String = "") {
    for (d in ds) {
        println(indent + d.render())
        printDiagnostics(d.causes, "$indent    ")
    }
}

private fun check(a: Args): Int = runBlocking {
    val core = core(backend(a.opt("--backend")))
    val text = a.file(0).readText()
    when (val r = core.importAndActivate(text)) {
        is Outcome.Failure -> {
            println("REJECTED (разбор/проверка)")
            printDiagnostics(r.diagnostics)
            1
        }
        is Outcome.Success -> {
            printDiagnostics(r.diagnostics)
            when (val act = r.value) {
                is ActivationResult.Activated -> {
                    println(
                        "ACTIVATED revision=${act.record.revision} profile=${act.record.profileId} compiled_sha256=${act.record.compiledChecksum?.take(16)}",
                    )
                    printDiagnostics(act.diagnostics)
                    core.tunnelSpec()?.valueOrNull()?.let { spec ->
                        println("tunnel: routes=${spec.routes.size} excluded=${spec.excludedRoutes.size} apps=${spec.apps} ipv6=${spec.ipv6Mode}")
                    }
                    0
                }
                is ActivationResult.Rejected -> {
                    println("REJECTED step=${act.record.failedStep}")
                    printDiagnostics(act.diagnostics)
                    1
                }
            }
        }
    }
}

private fun route(a: Args): Int {
    val loaded = ConfigLoader().load(a.file(0).readText())
    val ir = loaded.valueOrNull() ?: run {
        printDiagnostics(loaded.diagnostics)
        return 1
    }
    val ip = a.opt("--ip")?.let { IpAddress.parse(it) ?: throw UsageError("не IP: $it") }
    val domain = a.opt("--domain")?.lowercase()
    if (ip == null && domain == null) throw UsageError("нужен --domain или --ip")
    val network = a.opt("--network")?.let { n ->
        NetworkKind.entries.firstOrNull {
            it.name == n.uppercase()
        } ?: throw UsageError("сеть: wifi|mobile|ethernet|other")
    }
    val q = RouteQuery(
        domain = domain,
        ip = ip,
        port = a.opt("--port")?.toIntOrNull(),
        protocol = if (a.has("--udp")) TransportProtocol.UDP else TransportProtocol.TCP,
        packageName = a.opt("--app"),
        network = network,
    )
    val d = RouteEvaluator(ir.ir.routing).decide(q)
    println("${d.action} (${d.ruleId ?: "default"}): ${d.reason}")
    // Геоданных в cli нет (GeoResolver.None): правило с geoip/geosite здесь не срабатывает
    // никогда. Если такое правило стоит раньше решившего, с геоданными решение могло быть
    // другим — об этом говорится прямо, а не молчанием «ни одно правило не сработало».
    val rules = ir.ir.routing.rules
    val decidedAt = rules.indexOfFirst { it.id == d.ruleId }.takeIf { it >= 0 } ?: rules.size
    val unchecked = rules.take(decidedAt).filter { it.conditions.geoSites.isNotEmpty() || it.conditions.geoIps.isNotEmpty() }
    if (unchecked.isNotEmpty()) {
        println("примечание: правила с geoip/geosite не проверены — в dppass-cli нет геоданных: ${unchecked.joinToString { it.id.value }}")
    }
    return 0
}

private fun assess(condition: NetworkCondition, clock: ManualClock) = runBlocking {
    val net = SimulatedNetwork(condition, blockedEndpoints = setOf("203.0.113.10:443"))
    val assessor = NetworkAssessor(net, ProbeBudget(clock)) { clock.advance(it) }
    net to assessor.assess(NetworkType.MOBILE)
}

private fun classify(a: Args): Int {
    val (net, x) = assess(condition(a), ManualClock(1_000_000))
    println("restriction=${x.restriction} confidence=${x.confidence}")
    println("dns=${x.dns} tcp=${x.tcp} tls=${x.tls} udp=${x.udp} bulk=${x.bulk} captive=${x.captivePortal}")
    println("probes=${net.probeCount}")
    x.evidence.forEach { println("  - $it") }
    return 0
}

private fun plan(a: Args): Int = runBlocking {
    val clock = ManualClock(1_000_000)
    val core = core(MockBackend.FULL, clock)
    val act = core.importAndActivate(a.file(0).readText()).valueOrNull()
    if (act !is ActivationResult.Activated) {
        println("конфигурация не активирована")
        return@runBlocking 1
    }
    val (_, x) = assess(condition(a), clock)
    val p = core.plan(x) ?: return@runBlocking 1
    println("network: ${x.restriction} (${x.confidence})")
    p.attempts.forEachIndexed { i, at -> println("${i + 1}. ${at.profile.id} [${at.profile.transportClass}] — ${at.reasons.joinToString("; ")}") }
    p.excluded.forEach { println("   excluded ${it.profileId}: ${it.reason}") }
    p.verdict?.let { println("verdict: $it — ${p.verdictMessage}") }
    0
}

private fun connect(a: Args): Int = runBlocking {
    val clock = ManualClock(1_000_000)
    val core = core(MockBackend.FULL, clock)
    val act = core.importAndActivate(a.file(0).readText()).valueOrNull()
    if (act !is ActivationResult.Activated) return@runBlocking 1
    val (net, x) = assess(condition(a), clock)
    val report = core.connect(x, SimulatedHealthChecker(net), tun = null) { clock.advance(it) } ?: return@runBlocking 1
    for (r in report.attempts) {
        println("${if (r.ok) "OK  " else "FAIL"} ${r.profileId} — ${r.failure?.render() ?: "данные идут"}")
    }
    when (report) {
        is ConnectionReport.Connected -> {
            println("CONNECTED via ${report.profileId}")
            0
        }
        is ConnectionReport.Failed -> {
            println("FAILED: ${report.reason.render()}")
            1
        }
    }
}

private fun subscription(a: Args): Int = runBlocking {
    val clock = ManualClock(1_000_000)
    val core = core(backend(a.opt("--backend")), clock)
    val bytes = a.file(0).readBytes()
    val headers = a.opt("--headers")?.let { h ->
        (Json.parse(File(h).readText()) as? JsonObject)?.fields?.mapValues { (it.value as? JsonString)?.value ?: "" } ?: emptyMap()
    } ?: emptyMap()
    val fetcher = com.dpsmpx.dppass.subscriptions.SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(bytes, headers, clock.nowMillis())) }
    val sub = Subscription(SubscriptionId("cli"), "cli", SubscriptionSource.Url(Secret("https://sub.example.com/token")))
    val r = SubscriptionUpdater(fetcher, clock, CLI_VERSION).update(sub, core.profileFilter())
    printDiagnostics(r.diagnostics)
    when (r) {
        is UpdateResult.Ready -> {
            println("READY revision=${r.candidate.revision.number} profiles=${r.candidate.profiles.size} title=${r.candidate.metadata.title}")
            r.candidate.profiles.forEach { println("  ${it.id} ${it.name} [${it.transportClass}]") }
            0
        }
        is UpdateResult.Unchanged -> 0
        is UpdateResult.Failed -> {
            println("FAILED")
            1
        }
    }
}

private fun export(a: Args): Int {
    val loaded = ConfigLoader().load(a.file(0).readText())
    val ir = loaded.valueOrNull() ?: run {
        printDiagnostics(loaded.diagnostics)
        return 1
    }
    println(ConfigWriter.write(ir.ir, ConfigWriter.Mode.REDACTED))
    return 0
}

private fun report(a: Args): Int = runBlocking {
    val core = core(MockBackend.FULL)
    val r = core.importAndActivate(a.file(0).readText())
    val extra = when (r) {
        is Outcome.Failure -> r.diagnostics
        is Outcome.Success -> r.value.diagnostics
    }
    print(core.report(extra).render())
    0
}
