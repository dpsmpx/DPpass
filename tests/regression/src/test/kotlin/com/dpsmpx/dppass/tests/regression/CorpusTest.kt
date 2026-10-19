package com.dpsmpx.dppass.tests.regression

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.CandidatePlanner
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.EngineProfileFilter
import com.dpsmpx.dppass.connection.HealthBook
import com.dpsmpx.dppass.connection.SimulatedHealthChecker
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.Json
import com.dpsmpx.dppass.core.JsonArray
import com.dpsmpx.dppass.core.JsonBool
import com.dpsmpx.dppass.core.JsonNull
import com.dpsmpx.dppass.core.JsonNumber
import com.dpsmpx.dppass.core.JsonObject
import com.dpsmpx.dppass.core.JsonString
import com.dpsmpx.dppass.core.JsonValue
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.engine.xray.GeodataCodes
import com.dpsmpx.dppass.engine.xray.GeodataManifest
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkClassifier
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeRequest
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import com.dpsmpx.dppass.routing.AppLowering
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.routing.TableGeoResolver
import com.dpsmpx.dppass.routing.TransportProtocol
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionUpdater
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.tunnel.PlatformTraits
import java.io.File
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DynamicTest
import org.junit.jupiter.api.TestFactory

/**
 * Корпус регрессий (`docs/TESTING.md`): каждый файл в `tests/data/` с
 * ожиданием `*.expect.json` — отдельный тест. Новый баг — новый файл
 * корпуса, а не правка кода без следа.
 *
 * Эталоны компилятора Xray (`tests/data/xray/`, D-24) пишет и сверяет
 * этот же тест; принимает их само ядро — шаг hostcheck «Xray»
 * (`docs/TESTING.md`, «Эталоны Xray»).
 */
class CorpusTest {
    private val data = File(System.getProperty("dppass.repoRoot"), "tests/data")
    private val goldens = File(data, "xray")

    /** Перезапись эталонов вместо сверки — только намеренно, с обзором разницы в git. */
    private val updateGoldens = System.getProperty("dppass.golden.update") == "true"

    private fun json(f: File): JsonObject = Json.parse(f.readText()) as JsonObject
    private fun str(o: JsonObject, k: String): String? = (o[k] as? JsonString)?.value
    private fun codes(o: JsonObject?, key: String = "codes"): List<String> = (o?.get(key) as? JsonArray)?.items?.map { (it as JsonString).value }.orEmpty()

    /** Все коды дерева находок (с причинами). */
    private fun allCodes(ds: List<Diagnostic>): Set<String> = ds.flatMap { listOf(it.code.name) + allCodes(it.causes) }.toSet()

    private fun backend(name: String?): EngineCapabilities = if (name == "mock-limited") MockBackend.LIMITED else MockBackend.FULL

    private fun core(caps: EngineCapabilities) = DPpassCore(
        MockBackendCompiler(caps), MockProxyEngine(caps), InMemoryBlobStore(), ManualClock(1_000_000), "com.dpsmpx.dppass", PlatformTraits(true),
    )

    @TestFactory
    fun configsAndDns(): List<DynamicTest> = listOf("configs", "dns").flatMap { dir ->
        File(data, dir).listFiles { f -> f.name.endsWith(".expect.json") }!!.sorted().map { expectFile ->
            val name = expectFile.name.removeSuffix(".expect.json")
            DynamicTest.dynamicTest("$dir/$name") {
                val expect = json(expectFile)
                val text = File(expectFile.parentFile, "$name.json").readText()
                val load = expect["load"] as JsonObject
                val r = ConfigLoader().load(text)
                val got = allCodes(r.diagnostics)
                assertEquals(str(load, "outcome") == "ok", r.isSuccess, "исход разбора $name: ${r.diagnostics.map { it.render() }}")
                for (c in codes(load)) assertTrue(c in got, "$name: нет ожидаемого кода $c, есть $got")
                // Отказ — с той причиной, а не ещё и с ложной: `absent` не должно быть в дереве находок.
                for (c in codes(load, "absent")) assertFalse(c in got, "$name: лишний код $c, есть $got")
                if (str(load, "outcome") == "ok") {
                    val unexpected = r.diagnostics.filter { it.severity.name != "INFO" }.map { it.code.name }.toSet() - codes(load).toSet()
                    assertTrue(unexpected.isEmpty(), "$name: неожиданные находки $unexpected")
                }
                (expect["activate"] as? JsonObject)?.let { act ->
                    runBlocking {
                        val res = core(backend(str(act, "backend"))).importAndActivate(text).valueOrNull() ?: fail("$name: не разобран")
                        val ok = res is ActivationResult.Activated
                        assertEquals(str(act, "outcome") == "activated", ok, "$name: ${res.diagnostics.map { it.render() }}")
                        val gotA = allCodes(res.diagnostics)
                        for (c in codes(act)) assertTrue(c in gotA, "$name: активация без кода $c, есть $gotA")
                    }
                }
                (expect["xray"] as? JsonObject)?.let { xray ->
                    checkXray("$dir/$name", r.valueOrNull()?.ir ?: fail("$name: не разобран"), xray)
                }
            }
        }
    }

    /**
     * Компиляция для Xray: каждый профиль — с TUN, как на устройстве.
     * `compiled` — все профили скомпилированы без находок сверх `codes`, и
     * результат совпал с эталонами `tests/data/xray/<каталог>/<имя>/<профиль>.json`;
     * `rejected` — хотя бы один профиль отвергнут, коды — в находках компиляции.
     * `geodata` — оглавление набора в корпусе: коды и атрибуты сверяются с ним,
     * как на устройстве (D-27); без него — не сверяются, как на хосте.
     * `split_client_hello` — компиляция с разбиением ClientHello (D-68).
     * `split_sites` — список «Напрямую с разбиением» (D-72): записи настройки
     * телефона, разбираются как на телефоне.
     */
    private fun checkXray(where: String, ir: ConfigIr, expect: JsonObject) {
        val geodata = str(expect, "geodata")?.let { rel ->
            val manifest = GeodataManifest.parse(File(data, rel).readText())
            GeodataCodes.Installed(manifest.valueOrNull() ?: fail("Xray, $where: оглавление $rel не разобрано: ${manifest.diagnostics.map { it.render() }}"))
        } ?: GeodataCodes.Unchecked
        val compiler = XrayCompiler(geodata = geodata)
        val split = (expect["split_client_hello"] as? JsonBool)?.value == true
        val sites = (expect["split_sites"] as? JsonArray)?.let { list ->
            val text = list.items.joinToString("\n") { (it as JsonString).value }
            SplitSites.parse(text).valueOrNull() ?: fail("Xray, $where: split_sites не разобран: ${SplitSites.parse(text).diagnostics.map { it.render() }}")
        } ?: SplitSites.NONE
        val results = ir.profiles.map {
            it.id.value to compiler.compile(ir, CompilePlan(it.id, withTun = true, splitClientHello = split, splitSites = sites))
        }
        val diagnostics = results.flatMap { it.second.diagnostics }
        val got = allCodes(diagnostics)
        val compiled = results.all { it.second.isSuccess }
        assertEquals(str(expect, "outcome") == "compiled", compiled, "Xray, $where: ${diagnostics.map { it.render() }}")
        for (c in codes(expect)) assertTrue(c in got, "Xray, $where: нет кода $c, есть $got")
        val dir = File(goldens, where)
        if (updateGoldens) dir.deleteRecursively()
        if (!compiled) return
        val unexpected = got - codes(expect).toSet()
        assertTrue(unexpected.isEmpty(), "Xray, $where: неожиданные находки $unexpected")
        for ((id, outcome) in results) golden(File(dir, "$id.json"), outcome.valueOrNull()!!.payloadForEngine())
    }

    /** Эталон совпадает с тем, что выдал компилятор; в режиме перезаписи — записывается. */
    private fun golden(file: File, actual: String) {
        val rel = file.relativeTo(data)
        if (updateGoldens) {
            file.parentFile.mkdirs()
            file.writeText(actual)
            return
        }
        if (!file.isFile) fail("нет эталона tests/data/$rel — CorpusTest с -Ddppass.golden.update=true")
        val want = file.readText().lines()
        val have = actual.lines()
        val i = want.indices.firstOrNull { it >= have.size || want[it] != have[it] } ?: want.size
        if (want != have) {
            fail(
                "эталон tests/data/$rel разошёлся с компилятором в строке ${i + 1}: «${want.getOrNull(i)}» → «${have.getOrNull(i)}»; " +
                    "намеренное изменение — CorpusTest с -Ddppass.golden.update=true и обзор разницы",
            )
        }
    }

    @TestFactory
    fun subscriptions(): List<DynamicTest> =
        File(data, "subscriptions").listFiles { f -> f.name.endsWith(".expect.json") }!!.sorted().map { expectFile ->
            val name = expectFile.name.removeSuffix(".expect.json")
            DynamicTest.dynamicTest("subscriptions/$name") {
                val expect = json(expectFile)
                val body = File(expectFile.parentFile, "$name.txt").readBytes()
                val headersFile = File(expectFile.parentFile, "$name.headers.json")
                val headers = if (headersFile.isFile) json(headersFile).fields.mapValues { (it.value as JsonString).value } else emptyMap()
                val clock = ManualClock(0)
                val fetcher = SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(body, headers, 0)) }
                val sub = Subscription(SubscriptionId("corpus"), name, SubscriptionSource.Url(Secret("https://sub.example.com/corpus")))
                val r = runBlocking { SubscriptionUpdater(fetcher, clock, "test").update(sub, EngineProfileFilter(MockBackend.FULL)) }
                val got = allCodes(r.diagnostics)
                when (str(expect, "outcome")) {
                    "ready" -> {
                        val ready = r as? UpdateResult.Ready ?: fail("$name: ожидался Ready, есть $r")
                        assertEquals((expect["profiles"] as JsonNumber).toIntOrNull(), ready.candidate.profiles.size, "$name: число серверов")
                    }
                    "failed" -> assertTrue(r is UpdateResult.Failed, "$name: ожидался отказ")
                }
                for (c in codes(expect)) assertTrue(c in got, "$name: нет кода $c, есть $got")
            }
        }

    private fun routeQuery(q: JsonObject) = RouteQuery(
        domain = str(q, "domain"),
        ip = str(q, "ip")?.let(IpAddress::parse),
        port = (q["port"] as? JsonNumber)?.toIntOrNull(),
        protocol = str(q, "protocol")?.let { TransportProtocol.valueOf(it.uppercase()) },
        packageName = str(q, "package"),
    )

    @TestFactory
    fun routing(): List<DynamicTest> =
        File(data, "routing").listFiles { f -> f.name.endsWith(".cases.json") }!!.sorted().flatMap { casesFile ->
            val cases = json(casesFile)
            val ir = ConfigLoader().load(File(casesFile.parentFile, str(cases, "config")!!).readText()).valueOrNull()
                ?: fail("${casesFile.name}: конфигурация не разобрана")
            val geoIp = ((cases["geo"] as? JsonObject)?.get("geoip") as? JsonObject) ?: JsonObject(emptyMap())
            val geoIps = geoIp.fields.mapValues { (_, v) -> (v as JsonArray).items.map { Cidr.parse((it as JsonString).value)!!.cidr } }
            val evaluator = RouteEvaluator(ir.ir.routing, TableGeoResolver(ips = geoIps))
            val items = (cases["cases"] as JsonArray).items.map { it as JsonObject }
            items.mapIndexed { i, c ->
                val q = c["query"] as JsonObject
                DynamicTest.dynamicTest("routing/${casesFile.name}#$i ${Json.write(q, pretty = false)}") {
                    val d = evaluator.decide(routeQuery(q))
                    assertEquals(str(c, "action")!!.uppercase(), d.action.name, d.reason)
                    val rule = c["rule"]
                    assertEquals(if (rule == null || rule == JsonNull) null else (rule as JsonString).value, d.ruleId?.value)
                }
            } + DynamicTest.dynamicTest("xray/routing/${casesFile.name.removeSuffix(".cases.json")}.probe.json") {
                xrayProbe(casesFile, ir.ir, evaluator, geoIp, items)
            }
        }

    /**
     * Те же случаи — для сверки с Xray (шаг hostcheck «Xray»): эталон
     * конфигурации и `*.probe.json`, где ожидание — решение
     * `RouteEvaluator` в тегах Xray (исходящий и правило). Ядро видит
     * соединение из TUN без приложения-владельца; решение, принятое до
     * ядра (приложение вне туннеля — уровень VpnService, D-09), в сверку
     * не идёт и записывается в `skipped` с причиной.
     */
    private fun xrayProbe(casesFile: File, ir: ConfigIr, evaluator: RouteEvaluator, geoIp: JsonObject, items: List<JsonObject>) {
        val base = casesFile.name.removeSuffix(".cases.json")
        val compiled = XrayCompiler().compile(ir, CompilePlan(ir.profiles.first().id, withTun = true))
        val config = compiled.valueOrNull() ?: fail("$base: не компилируется для Xray: ${compiled.diagnostics.map { it.render() }}")
        val tunnelApps = AppLowering.lower(ir.routing).tunnelApps
        val checked = mutableListOf<JsonValue>()
        val skipped = mutableListOf<JsonValue>()
        for ((i, c) in items.withIndex()) {
            val query = routeQuery(c["query"] as JsonObject)
            val pkg = query.packageName
            if (pkg != null && !tunnelApps.includes(pkg)) {
                skipped += Json.obj("case" to Json.num(i), "reason" to Json.str("приложение $pkg вне туннеля: решает VpnService, до ядра"))
                continue
            }
            val d = evaluator.decide(query)
            checked += Json.obj(
                "case" to Json.num(i),
                "query" to Json.obj(
                    "domain" to Json.str(query.domain),
                    "ip" to Json.str(query.ip?.toString()),
                    "port" to query.port?.let(Json::num),
                    "network" to Json.str(query.protocol?.name?.lowercase()),
                ),
                "outbound" to Json.str(XrayBackend.outboundTag(d.action)),
                "rule" to (d.ruleId?.value?.let(::JsonString) ?: JsonNull),
            )
        }
        val probe = Json.obj(
            "source" to Json.str("routing/${casesFile.name}"),
            "config" to Json.str("$base.config.json"),
            "inbound" to Json.str(XrayBackend.TAG_TUN_IN),
            "geo" to Json.obj("geoip" to geoIp, "geosite" to JsonObject(emptyMap())),
            "cases" to Json.arr(checked),
            "skipped" to Json.arr(skipped),
        )
        golden(File(goldens, "routing/$base.config.json"), config.payloadForEngine())
        golden(File(goldens, "routing/$base.probe.json"), Json.write(probe, pretty = true) + "\n")
    }

    /** Наблюдения проб с устройства (D-60): исходы без адресов → класс, как у классификатора на телефоне. */
    @TestFactory
    fun networkObservations(): List<DynamicTest> {
        val dir = File(data, "network/observations")
        return dir.listFiles { f -> f.name.endsWith(".json") }.orEmpty().sortedBy { it.name }.map { f ->
            DynamicTest.dynamicTest("network/observations/${f.name}") {
                val o = json(f)
                val probes = (o["probes"] as JsonArray).items.map { item ->
                    val pr = item as JsonObject
                    ProbeResult(
                        ProbeRequest(ProbeKind.valueOf(str(pr, "kind")!!), ProbeTarget.valueOf(str(pr, "target")!!)),
                        ProbeOutcome.valueOf(str(pr, "outcome")!!),
                        (pr["ms"] as? JsonNumber)?.toLongOrNull(),
                    )
                }
                val x = NetworkClassifier.classify(NetworkType.valueOf(str(o, "type")!!), probes)
                assertEquals(str(o, "restriction"), x.restriction.name, "${f.name}: ${x.evidence}")
                str(o, "confidence")?.let { assertEquals(it, x.confidence.name, "${f.name}: уверенность") }
                assertTrue(x.evidence.isNotEmpty(), "${f.name}: вывод без доводов")
            }
        }
    }

    @TestFactory
    fun networkConditions(): List<DynamicTest> {
        val table = json(File(data, "network/conditions.json"))
        val configText = File(data, "network/" + str(table, "config")!!).readText()
        return (table["conditions"] as JsonArray).items.map { item ->
            val c = item as JsonObject
            val cond = NetworkCondition.valueOf(str(c, "condition")!!)
            DynamicTest.dynamicTest("network/${cond.name}") {
                runBlocking {
                    val clock = ManualClock(1_000_000)
                    val blocked = (c["blocked_endpoints"] as? JsonArray)?.items?.map { (it as JsonString).value }?.toSet().orEmpty()
                    val net = SimulatedNetwork(cond, blocked)
                    val x = NetworkAssessor(net, ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE)
                    assertEquals(str(c, "restriction"), x.restriction.name, "${cond.name}: ${x.evidence}")
                    for (k in listOf("dns", "udp", "tls")) {
                        str(c, k)?.let { want ->
                            val got = when (k) { "dns" -> x.dns; "udp" -> x.udp; else -> x.tls }
                            assertEquals(want, got.name, "${cond.name}.$k")
                        }
                    }
                    val core = core(MockBackend.FULL)
                    core.importAndActivate(configText)
                    val ir = core.activation.state.activeConfig!!
                    val plan = CandidatePlanner.plan(ir, MockBackend.FULL, x, HealthBook(), null, clock.nowMillis())
                    (c["excluded"] as? JsonArray)?.items?.forEach { e ->
                        assertTrue(plan.excluded.any { it.profileId.value == (e as JsonString).value }, "${cond.name}: не исключён $e")
                    }
                    str(c, "only_candidate")?.let { assertEquals(listOf(it), plan.attempts.map { a -> a.profile.id.value }) }
                    str(c, "first_attempt_class")?.let { assertEquals(it, plan.attempts.first().profile.transportClass.name) }
                    val report = core.connect(x, SimulatedHealthChecker(net), null) { clock.advance(it) }!!
                    val connects = (c["connects"] as JsonBool).value
                    assertEquals(connects, report is ConnectionReport.Connected, "${cond.name}: ${report.attempts}")
                    str(c, "verdict")?.let { assertEquals(it, (report as ConnectionReport.Failed).reason.code.name) }
                    str(c, "first_failed")?.let { assertEquals(it, report.attempts.first { a -> !a.ok }.profileId.value) }
                }
            }
        }
    }
}
