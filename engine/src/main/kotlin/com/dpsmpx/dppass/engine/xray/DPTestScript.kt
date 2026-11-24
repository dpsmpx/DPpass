package com.dpsmpx.dppass.engine.xray

/**
 * DPTest Script v1. Deliberately NOT a general-purpose interpreter:
 * no imports, expressions, functions, loops, reflection, files or shell.
 * Every script is fully expanded and budget-checked BEFORE any network IO.
 *
 * Native also checks every target, IP index, method, certificate and timeout.
 * Names and paths are not used as network inputs outside the explicit grammar.
 */
object DPTestScript {
    const val MAX_TEXT = 16_384
    const val MAX_SCENARIOS = 8
    const val MAX_PROBES = 96
    const val MAX_WALL_MS = 240_000L
    const val MAX_IPS = 8
    const val MAX_ATTEMPTS = 3

    val tcpMethods = listOf(
        "plain", "split-1", "split", "tlsrec-split",
        "fake-3", "fake-5", "disorder",
    )
    val udpMethods = listOf("plain", "fake-3", "fake-5")

    // These primitives have real protected JNI/Go implementations.
    // A similarly named upstream nfqws/ByeDPI operation is NOT assumed
    // to be equivalent merely because it has a similar name.
    val protocols = linkedMapOf(
        "h1" to "h1",
        "h2" to "h2",
        "tls12" to "t12",
        "tls13" to "t13",
        "google-h1" to "gh1",
        "google-h2" to "gh2",
        "google-tls12" to "g12",
        "google-tls13" to "g13",
        "quic1" to "q1",
        "quic2" to "q2",
        "h3-get" to "h3",
        "h3-browse" to "h3api",
    )
    val upstreamOnly = linkedSetOf(
        "multisplit", "multidisorder", "fakedsplit", "fakeddisorder",
        "hostfakesplit", "syndata", "seqovl", "badseq", "md5sig",
        "tcp-md5", "tcp-urg", "oob", "oob-disorder", "udp-fake",
        "ipfrag", "reverse-frag", "tcp-timestamp", "wssize",
        "autottl", "tls-mod", "rndsni", "dupsid", "nfqws2-lua",
    )

    data class Scenario(
        val host: String,
        val ipCount: Int,
        val attempts: Int,
        val timeoutMillis: Int,
        val methods: List<String>,
        val protocols: List<String>,
        val trainingMethod: String?,
        val stopOnVerified: Boolean,
        val steps: List<Step>,
    )

    data class Step(
        val ipIndex: Int,
        val attempt: Int,
        val method: String,
        val protocol: String,
        val nativeTarget: String,
    )

    data class Program(
        val title: String,
        val source: String,
        val scenarios: List<Scenario>,
    ) {
        val steps: Int get() = scenarios.sumOf { it.steps.size }
        val budgetMillis: Long get() = scenarios.sumOf {
            it.steps.size.toLong() * it.timeoutMillis
        }
        fun preview(): String = buildString {
            appendLine("DPTest Script 1 — " + title)
            appendLine("План: " + scenarios.size + " сценариев, " + steps +
                " соединений; максимальный бюджет: " + budgetMillis + " мс")
            scenarios.forEachIndexed { i, item ->
                appendLine("  " + (i + 1) + ". " + item.host + " · IP=" +
                    item.ipCount + " · attempts=" + item.attempts +
                    " · timeout=" + item.timeoutMillis + "ms")
                appendLine("     methods=" + item.methods.joinToString(","))
                appendLine("     protocols=" + item.protocols.joinToString(","))
                appendLine("     neural=" + (item.trainingMethod ?: "off") +
                    " (только проверенные 3/3, не AUTO)")
            }
            appendLine("Все IP берутся из защищённого DoH; приватные IP запрещены.")
            appendLine("Скрипт не меняет VPN, DNS, подписки, AUTO и QUIC маршруты.")
            appendLine("Логи автоматически копируются в буфер обмена.")
        }
    }

    private data class Builder(
        val host: String,
        var ips: Int = 2,
        var attempts: Int = 3,
        var timeout: Int = 5_000,
        var methods: List<String> = listOf("plain", "tlsrec-split", "fake-5"),
        var protocols: List<String> = listOf("h1"),
        var train: String? = null,
        var stop: Boolean = false,
    )

    private fun hostIsValid(host: String): Boolean {
        if (host.length !in 4..253 || host != host.lowercase() ||
            host.any { it in ":/@\\%?# \t\r\n" }) return false
        val labels = host.split('.')
        if (labels.size < 2 || labels.any {
                it.length !in 1..63 || it.first() == '-' ||
                    it.last() == '-' || it.any { c ->
                    !(c in 'a'..'z' || c in '0'..'9' || c == '-')
                }
            }) return false
        val tld = labels.last()
        if (tld.length < 2 || (tld.startsWith("xn--") && tld.length < 6) ||
            (!tld.startsWith("xn--") && tld.any { it !in 'a'..'z' }))
            return false
        if (tld in setOf("local", "localhost", "internal", "lan", "home",
                "test", "invalid", "example", "onion", "arpa") ||
            host.endsWith(".home.arpa")) return false
        if (host.matches(Regex("[0-9.]+"))) return false
        return true
    }

    private fun csv(value: String): List<String> {
        val items = value.split(',').map { it.trim() }
        require(items.isNotEmpty() && items.size <= 16 &&
            items.all { it.isNotEmpty() } && items.size == items.distinct().size) {
            "Недопустимый или повторяющийся список: " + value.take(100)
        }
        return items
    }

    private fun compile(builder: Builder): Scenario {
        require(builder.ips in 1..MAX_IPS && builder.attempts in 1..MAX_ATTEMPTS)
        val udp = setOf("quic1", "quic2", "h3-get", "h3-browse")
        for (method in builder.methods) for (proto in builder.protocols) {
            require(method in (if (proto in udp) udpMethods else tcpMethods)) {
                "Метод " + method + " не реализован для " + proto
            }
            require(proto !in setOf("h3-get", "h3-browse") ||
                builder.host == "youtubei.googleapis.com") {
                "HTTP/3 GET/POST ограничен фиксированным YouTube API"
            }
        }
        if (builder.train != null) {
            require(builder.train != "plain" && builder.train in builder.methods &&
                "plain" in builder.methods && "h1" in builder.protocols &&
                builder.attempts == 3 && builder.ips <= 2 &&
                builder.protocols == listOf("h1")) {
                "Обучение: только h1, plain + один поддерживаемый метод, IP <=2, attempts=3"
            }
        }
        val steps = ArrayList<Step>()
        // Interleave by IP and attempt: same-path comparisons stay near
        // in time and cannot accidentally reuse a TLS connection.
        for (ip in 0 until builder.ips)
            for (attempt in 1..builder.attempts)
                for (protocol in builder.protocols)
                    for (method in builder.methods) {
                        val id = "dpts_" + protocols.getValue(protocol) + "_ip" +
                            ip.toString().padStart(2, '0') + "_a" + attempt +
                            "_:" + builder.host
                        steps += Step(ip, attempt, method, protocol, id)
                    }
        return Scenario(builder.host, builder.ips, builder.attempts,
            builder.timeout, builder.methods, builder.protocols,
            builder.train, builder.stop, steps)
    }

    fun parse(source: String): Program {
        require(source.length in 8..MAX_TEXT && '\u0000' !in source) {
            "Сценарий пустой, содержит недопустимые символы или слишком длинный"
        }
        var title = "Пользовательский тест"
        var current: Builder? = null
        val scenarios = ArrayList<Scenario>()
        var header = false
        fun commit() {
            current?.let { scenarios += compile(it) }
            current = null
        }
        source.lines().forEachIndexed { position, raw ->
            val line = raw.trim()
            if (line.isEmpty() || line.startsWith("#")) return@forEachIndexed
            require(line.length <= 500 && line.none { it.code < 32 }) {
                "Строка " + (position + 1) + ": недопустимые символы"
            }
            val parts = line.split(Regex("\\s+"), limit = 2)
            val key = parts.first().lowercase()
            val value = parts.getOrNull(1)?.trim() ?: ""
            try {
                if (!header) {
                    require(line == "dptest 1") { "Первая команда должна быть dptest 1" }
                    header = true
                    return@forEachIndexed
                }
                when (key) {
                    "name" -> {
                        require(current == null && scenarios.isEmpty() &&
                            value.length in 1..80)
                        title = value.removeSurrounding("\"")
                    }
                    "scenario" -> {
                        require(hostIsValid(value)) { "Нужен публичный DNS-домен, не URL/IP" }
                        commit()
                        require(scenarios.size < MAX_SCENARIOS)
                        current = Builder(value)
                    }
                    "ips" -> {
                        require(current != null)
                        current!!.ips = value.toInt().also { require(it in 1..MAX_IPS) }
                    }
                    "attempts" -> {
                        require(current != null)
                        current!!.attempts = value.toInt().also {
                            require(it in 1..MAX_ATTEMPTS)
                        }
                    }
                    "timeout_ms" -> {
                        require(current != null)
                        current!!.timeout = value.toInt().also {
                            require(it in 1000..15000)
                        }
                    }
                    "methods" -> {
                        require(current != null)
                        val values = csv(value)
                        values.forEach { method ->
                            require(method in tcpMethods) {
                                if (method in upstreamOnly)
                                    "Метод " + method + " известен, но не реализован в защищённом движке"
                                else "Неизвестный метод: " + method
                            }
                        }
                        current!!.methods = values
                    }
                    "protocols" -> {
                        require(current != null)
                        val values = csv(value)
                        require(values.all { it in protocols }) {
                            "Неизвестный протокол; допустимы " + protocols.keys.joinToString(",")
                        }
                        current!!.protocols = values
                    }
                    "train" -> {
                        require(current != null)
                        current!!.train = if (value == "off") null else {
                            require(value.startsWith("verified "))
                            value.removePrefix("verified ").also {
                                require(it in tcpMethods)
                            }
                        }
                    }
                    "stop" -> {
                        require(current != null)
                        require(value == "never" || value == "first_verified")
                        current!!.stop = value == "first_verified"
                    }
                    "report" -> {
                        // Deliberately no switch for unredacted logs.
                        require(value == "redacted+clipboard")
                    }
                    else -> error("Неизвестная инструкция: " + key)
                }
            } catch (e: IllegalArgumentException) {
                throw IllegalArgumentException(
                    "Строка " + (position + 1) + ": " +
                        (e.message ?: "ошибка параметров"), e)
            } catch (e: IllegalStateException) {
                throw IllegalArgumentException(
                    "Строка " + (position + 1) + ": " +
                        (e.message ?: "ошибка сценария"), e)
            }
        }
        require(header) { "Нет заголовка dptest 1" }
        commit()
        require(scenarios.isNotEmpty()) { "Добавьте scenario <публичный-домен>" }
        require(scenarios.size <= MAX_SCENARIOS)
        val program = Program(title, source, scenarios)
        require(program.steps <= MAX_PROBES &&
            program.budgetMillis <= MAX_WALL_MS) {
            "Превышен лимит: максимум " + MAX_PROBES +
                " соединений или " + MAX_WALL_MS + " мс. Уменьшите ips/attempts/methods."
        }
        return program
    }

    fun verified(result: Zapret2GoogleProbe): Boolean =
        result.outcome == "ok" && result.httpStatus in 200..299 &&
            result.tlsStage == "tls_verified" && result.bodyBytes >= 128

    fun transport(result: Zapret2GoogleProbe): Boolean =
        result.tlsStage == "tls_verified" && result.httpStatus in 200..499 &&
            result.outcome in setOf("ok", "http_reachable", "redirect")

    fun report(program: Program, network: String,
        entries: List<ReportEntry>, completed: Boolean): String = buildString {
        appendLine("=== DPpass — DPTest Script 1 ===")
        appendLine("name=" + program.title + " network=" + network)
        appendLine("planned=" + program.steps + " executed=" + entries.size +
            " complete=" + completed)
        appendLine("No global DNS/routes/AUTO changes; all sockets protected.")
        program.scenarios.forEachIndexed { i, scenario ->
            val rows = entries.filter { it.scenario == i && it.step != null }
            val prep = entries.firstOrNull { it.scenario == i && it.step == null }
            appendLine("scenario=" + i + " host=" + scenario.host +
                " DoH=" + (prep?.result?.outcome ?: "not_run") +
                " IPv4=" + (prep?.result?.dnsAnswers ?: 0) +
                " fingerprint=" + (prep?.result?.dnsFingerprint ?: "-"))
            for (proto in scenario.protocols) for (method in scenario.methods) {
                val group = rows.filter {
                    it.step?.protocol == proto && it.step.method == method
                }
                appendLine("  " + proto + "/" + method +
                    " content=" + group.count { verified(it.result) } +
                    "/" + group.size + " http=" +
                    group.count { transport(it.result) } + "/" + group.size)
            }
            entries.filter { it.scenario == i && it.step != null }
                .forEach { row ->
                    val r = row.result
                    val step = requireNotNull(row.step)
                    appendLine("  ip_index=" + r.ipIndex + " protocol=" + step.protocol +
                        " method=" + step.method + " attempt=" + step.attempt +
                        " outcome=" + r.outcome + " stage=" + r.tlsStage +
                        " alpn=" + r.alpn + " http=" + r.httpStatus +
                        " body_bytes_bounded=" + r.bodyBytes +
                        " elapsed_ms=" + r.elapsedMillis)
                }
            val trained = entries.firstOrNull { it.scenario == i && it.training }
            appendLine("neural=" + (trained?.result?.outcome ?: "not_requested") +
                " requested=" + (scenario.trainingMethod ?: "off"))
        }
        appendLine("AUTO: not_applied (only explicit verified neural training can update model).")
        appendLine("TLS/HTTP transport alone is not proof of working API/login/feed/video.")
        appendLine("No IP, paths, headers, cookies, tokens, certificates or bodies are exported.")
    }

    data class ReportEntry(
        val scenario: Int,
        val step: Step?,
        val result: Zapret2GoogleProbe,
        val training: Boolean = false,
    )
}

/** Compiled text-only presets: same execution path as pasted user scripts. */
object DPTestPresets {
    val examples: LinkedHashMap<String, String> = linkedMapOf(
        "01 · HTTPS 7 методов" to """
dptest 1
name "HTTPS strategy matrix"
scenario www.youtube.com
ips 2
attempts 3
timeout_ms 5000
methods plain,split-1,split,tlsrec-split,fake-3,fake-5,disorder
protocols h1
train off
report redacted+clipboard
""".trimIndent(),
        "02 · CDN JPEG" to """
dptest 1
name "YouTube CDN JPEG and API"
scenario i.ytimg.com
ips 2
attempts 3
methods plain,tlsrec-split
protocols h1
scenario youtubei.googleapis.com
ips 2
attempts 1
methods plain,tlsrec-split
protocols h1
report redacted+clipboard
""".trimIndent(),
        "03 · API 8 IPv4, H1/H2" to """
dptest 1
name "API eight IPv4 H1/H2"
scenario youtubei.googleapis.com
ips 8
attempts 1
timeout_ms 5000
methods plain,tlsrec-split,fake-5
protocols h1,h2
report redacted+clipboard
""".trimIndent(),
        "04 · API SNI Google control" to """
dptest 1
name "API vs Google on same public IP"
scenario youtubei.googleapis.com
ips 2
attempts 3
methods plain
protocols h1,google-h1
report redacted+clipboard
""".trimIndent(),
        "05 · TLS 1.2/1.3" to """
dptest 1
name "API TLS version and SNI"
scenario youtubei.googleapis.com
ips 2
attempts 3
methods plain
protocols tls12,google-tls12,tls13,google-tls13
report redacted+clipboard
""".trimIndent(),
        "06 · QUIC versions" to """
dptest 1
name "YouTube QUIC v1 and v2"
scenario youtubei.googleapis.com
ips 2
attempts 3
methods plain,fake-5
protocols quic1,quic2
report redacted+clipboard
""".trimIndent(),
        "07 · HTTP/3 GET+POST" to """
dptest 1
name "YouTube H3 transport and anonymous API POST"
scenario youtubei.googleapis.com
ips 2
attempts 2
methods plain,fake-5
protocols h3-get,h3-browse
report redacted+clipboard
""".trimIndent(),
        "08 · Обучение (строгие 3/3)" to """
dptest 1
name "Verified HTML + neural learning"
scenario www.youtube.com
ips 2
attempts 3
methods plain,tlsrec-split
protocols h1
train verified tlsrec-split
report redacted+clipboard
""".trimIndent(),
    )
}
