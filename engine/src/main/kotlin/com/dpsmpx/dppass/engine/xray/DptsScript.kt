package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog

/**
 * DPTS/1 is deliberately NOT a general-purpose programming language.
 * It is a statically expanded, bounded, auditable matrix of protected probes.
 * No filesystem, shell, reflection, network URL, imports, variables, or loops
 * that can escape the validated finite operations are accepted.
 */
data class DptsProbe(
    val target: String,
    val method: String,
    val phase: String,
    val protocol: String,
    val ipIndex: Int,
    val attempt: Int,
    val timeoutMs: Int,
) {
    // TLS version is a plan dimension, not a wire protocol.
    val wireProtocol: String get() = when (protocol) {
        "tls12", "tls13" -> "h1"
        else -> protocol
    }

    fun matches(row: Zapret2GoogleAttempt): Boolean =
        row.target == target && row.strategy == method &&
            row.attempt == attempt && row.result.ipIndex == ipIndex &&
            row.result.protocol == wireProtocol

    fun handshakeVerified(result: Zapret2GoogleProbe): Boolean =
        when (wireProtocol) {
            "quic" -> result.outcome == "quic_verified" &&
                result.tlsStage == "quic_tls_verified" && result.alpn == "h3"
            "h1" -> result.tlsStage == "tls_verified" && result.alpn == "http/1.1"
            "h2" -> result.tlsStage == "tls_verified" && result.alpn == "h2"
            else -> false
        }

    fun boundedHttpsSuccess(result: Zapret2GoogleProbe): Boolean =
        phase == "https" && protocol in setOf("h1", "h2") &&
            handshakeVerified(result) && result.outcome == "ok" &&
            result.httpStatus in 200..299 && result.bodyBytes in 128L..256L
}

data class DptsPlan(
    val title: String,
    val host: String,
    val probes: List<DptsProbe>,
    val budgetMs: Long,
    /** Observe means export redacted, labelled evidence; NOT model updates. */
    val observeLearning: Boolean,
    /** Built-in migrated routine, selectable only from the finite registry. */
    val suite: String? = null,
)

class DptsCompileException(val line: Int, reason: String) :
    IllegalArgumentException("DPTS line $line: $reason")

object DptsScript {
    const val HEADER = "dpts 1"
    const val MAX_SOURCE_LENGTH = 12_000
    const val MAX_PROBES = 64
    const val MAX_BUDGET_MS = 240_000L
    private val allowedMethods = Zapret2ProbeCatalog.scriptTcpMethods
    private val allowedQuic = Zapret2ProbeCatalog.scriptQuicMethods
    private val supported = setOf("https", "tls", "quic", "sni")
    // Fixed routines do not consume an arbitrary host from the script.
    // The two site searches do; null marks precisely those two cases.
    private val suiteHosts: Map<String, String?> = mapOf(
        "google_youtube" to "www.google.com",
        "dns_compare" to Zapret2SiteSearch.YOUTUBE_API_HOST,
        "ip_matrix" to Zapret2SiteSearch.YOUTUBE_API_HOST,
        "h3_api" to Zapret2SiteSearch.YOUTUBE_API_HOST,
        "site_https" to null,
        "site_quic" to null,
        "api_ipv4_sweep" to Zapret2SiteSearch.YOUTUBE_API_HOST,
        "sni_control" to Zapret2SiteSearch.YOUTUBE_API_HOST,
        "tls_versions" to Zapret2SiteSearch.YOUTUBE_API_HOST,
    )
    val suites: Set<String> = suiteHosts.keys
    private val optionPattern = Regex("[a-z_]+=[a-zA-Z0-9,._-]+")

    fun compile(source: String): DptsPlan {
        if (source.length > MAX_SOURCE_LENGTH)
            throw DptsCompileException(0, "script exceeds 12,000 characters")
        // Keep original source positions when skipping comments and blanks.
        val lines = source.lineSequence().mapIndexed { index, text -> (index + 1) to text.trim() }
            .filter { (_, text) -> text.isNotEmpty() && !text.startsWith("#") }.toList()
        val header = lines.firstOrNull()
        if (header?.second != HEADER)
            throw DptsCompileException(header?.first ?: 1, "expected 'dpts 1'")
        if (lines.size > 40) throw DptsCompileException(lines[40].first, "too many statements")

        var name = "DPTS diagnostic"
        var host: String? = null
        var observe = false
        var named = false
        var learned = false
        var suite: String? = null
        val probes = ArrayList<DptsProbe>()
        val emitted = HashSet<Pair<String, String>>()
        var budget = 0L

        fun csv(line: Int, value: String, allowed: Set<String>): List<String> {
            val result = value.split(',')
            if (result.isEmpty() || result.any { it !in allowed } ||
                result.size != result.distinct().size)
                throw DptsCompileException(line, "unsupported or duplicate value: $value")
            return result
        }

        fun positive(line: Int, key: String, value: String?, max: Int,
            fallback: Int): Int {
            if (value == null) return fallback
            val parsed = value.toIntOrNull()
            if (parsed == null || parsed !in 1..max)
                throw DptsCompileException(line, "$key must be 1..$max")
            return parsed
        }

        for (index in 1 until lines.size) {
            val (lineNo, line) = lines[index]
            when {
                line.startsWith("name ") -> {
                    if (named || probes.isNotEmpty() || suite != null)
                        throw DptsCompileException(lineNo, "name must appear once before probes")
                    val rawTitle = line.removePrefix("name ").trim()
                    val quoted = rawTitle.startsWith('"') && rawTitle.endsWith('"') && rawTitle.length >= 2
                    val title = if (quoted) rawTitle.substring(1, rawTitle.length - 1) else rawTitle
                    if (title.isBlank() || title.length > 80 || title.any {
                            it == '"' || it.isISOControl() ||
                                it.category in setOf(CharCategory.FORMAT, CharCategory.LINE_SEPARATOR,
                                    CharCategory.PARAGRAPH_SEPARATOR)
                        })
                        throw DptsCompileException(lineNo, "invalid title")
                    name = title
                    named = true
                }
                line.startsWith("host ") -> {
                    if (host != null || probes.isNotEmpty() || suite != null)
                        throw DptsCompileException(lineNo, "host must appear once before probes")
                    val canonical = Zapret2SiteSearch.normalizedHost(
                        line.removePrefix("host ").trim())
                    host = canonical ?: throw DptsCompileException(lineNo,
                        "only a valid public DNS hostname is allowed")
                }
                line.startsWith("learn ") -> {
                    if (learned || probes.isNotEmpty() || suite != null)
                        throw DptsCompileException(lineNo, "learn must appear once before probes")
                    val mode = line.removePrefix("learn ").trim()
                    if (mode != "off" && mode != "observe")
                        throw DptsCompileException(lineNo, "learn supports off or observe only")
                    observe = mode == "observe"
                    learned = true
                }
                line.startsWith("suite ") -> {
                    if (suite != null || probes.isNotEmpty())
                        throw DptsCompileException(lineNo, "suite must be the only operation")
                    val currentHost = host ?: throw DptsCompileException(lineNo,
                        "declare host before suite")
                    val id = line.removePrefix("suite ").trim()
                    if (id !in suites)
                        throw DptsCompileException(lineNo, "unknown built-in suite: $id")
                    val fixedHost = suiteHosts[id]
                    if (fixedHost != null && currentHost != fixedHost)
                        throw DptsCompileException(lineNo, "this suite requires $fixedHost")
                    suite = id
                }
                else -> {
                    if (suite != null) throw DptsCompileException(lineNo,
                        "suite cannot be mixed with individual probes")
                    val currentHost = host ?: throw DptsCompileException(lineNo,
                        "declare host before the first probe")
                    val parts = line.split(Regex("\\s+"))
                    val kind = parts.first()
                    if (kind !in supported)
                        throw DptsCompileException(lineNo, "unknown operation: $kind")
                    val options = LinkedHashMap<String, String>()
                    for (token in parts.drop(1)) {
                        if (!optionPattern.matches(token))
                            throw DptsCompileException(lineNo, "invalid option syntax")
                        val key = token.substringBefore('=')
                        val value = token.substringAfter('=')
                        if (options.put(key, value) != null)
                            throw DptsCompileException(lineNo, "duplicate option $key")
                    }
                    val allowedOptions = when (kind) {
                        "https" -> setOf("protocols", "methods", "ips", "attempts", "timeout_ms")
                        "quic" -> setOf("methods", "ips", "attempts", "timeout_ms")
                        "tls" -> setOf("versions", "methods", "ips", "attempts",
                            "timeout_ms", "compare_google")
                        else -> setOf("ips", "attempts", "timeout_ms")
                    }
                    val unknown = options.keys - allowedOptions
                    if (unknown.isNotEmpty())
                        throw DptsCompileException(lineNo, "unsupported options: $unknown")
                    val ipsMax = if (kind == "sni" || kind == "tls") 2 else 8
                    val ips = positive(lineNo, "ips", options["ips"], ipsMax,
                        if (kind == "sni" || kind == "tls") 2 else 2)
                    val attempts = positive(lineNo, "attempts", options["attempts"],
                        3, 3)
                    val timeoutMs = positive(lineNo, "timeout_ms", options["timeout_ms"],
                        12_000, 5_000)
                    if (timeoutMs < 1_000)
                        throw DptsCompileException(lineNo, "timeout_ms must be >= 1000")
                    val methods = if (kind == "sni") listOf("plain")
                        else csv(lineNo, options["methods"] ?: "plain",
                            if (kind == "quic") allowedQuic else allowedMethods)
                    val protocols = if (kind == "https")
                        csv(lineNo, options["protocols"] ?: "h1", setOf("h1", "h2"))
                        else listOf(if (kind == "quic") "quic" else "h1")
                    val versions = if (kind == "tls")
                        csv(lineNo, options["versions"] ?: "12,13", setOf("12", "13"))
                        else emptyList()
                    val google = when (options["compare_google"]) {
                        null, "false" -> false
                        "true" -> true
                        else -> throw DptsCompileException(lineNo,
                            "compare_google must be true or false")
                    }
                    if ((kind == "sni" || google) &&
                        currentHost != Zapret2SiteSearch.YOUTUBE_API_HOST)
                        throw DptsCompileException(lineNo,
                            "same-IP Google controls are only supported for YouTube API")
                    if (google && methods != listOf("plain"))
                        throw DptsCompileException(lineNo,
                            "Google TLS control requires method=plain")

                    fun emit(target: String, method: String, phase: String,
                        protocol: String, ip: Int, attempt: Int) {
                        // A native attempt is identified by target and method.
                        // Repeating a statement must not create ambiguous evidence.
                        if (!emitted.add(target to method))
                            throw DptsCompileException(lineNo, "duplicate probe target and method")
                        val nextSize = probes.size + 1
                        val nextBudget = budget + timeoutMs.toLong()
                        if (nextSize > MAX_PROBES || nextBudget > MAX_BUDGET_MS)
                            throw DptsCompileException(lineNo,
                                "limit exceeded: 64 sockets or 240 seconds worst case")
                        probes.add(DptsProbe(target, method, phase,
                            protocol, ip, attempt, timeoutMs))
                        budget = nextBudget
                    }
                    for (ip in 0 until ips) {
                        for (attempt in 1..attempts) {
                            when (kind) {
                                "https" -> for (protocol in protocols)
                                    for (method in methods)
                                        emit(scriptTarget(currentHost, protocol, ip, attempt),
                                            method, "https", protocol, ip, attempt)
                                "quic" -> for (method in methods)
                                    emit(scriptTarget(currentHost, "quic", ip, attempt),
                                        method, "quic", "quic", ip, attempt)
                                "tls" -> for (version in versions)
                                    for (method in methods) {
                                        val protocol = "tls$version"
                                        emit(scriptTarget(currentHost, protocol, ip, attempt),
                                            method, "tls", protocol, ip, attempt)
                                        if (google)
                                            emit(Zapret2SiteSearch.tlsVersionTrial(
                                                ip, attempt, version.toInt(), true),
                                                "plain", "tls_google", protocol, ip, attempt)
                                    }
                                "sni" -> {
                                    emit(scriptTarget(currentHost, "h1", ip, attempt),
                                        "plain", "sni_api", "h1", ip, attempt)
                                    emit(Zapret2SiteSearch.sameIpControlTrial(ip, attempt),
                                        "plain", "sni_google", "h1", ip, attempt)
                                }
                            }
                        }
                    }
                }
            }
        }
        if (host == null) throw DptsCompileException(1, "missing host")
        if (probes.isEmpty() && suite == null)
            throw DptsCompileException(1, "no probes declared")
        return DptsPlan(name, host, probes, budget, observe, suite)
    }

    private fun scriptTarget(host: String, kind: String, ip: Int, attempt: Int): String {
        require(kind in setOf("h1", "h2", "tls12", "tls13", "quic"))
        require(ip in 0..7 && attempt in 1..3)
        return "site_script_${kind}_ip" + ip.toString().padStart(2, '0') +
            "_a${attempt}_:$host"
    }

    /** The address set is fixed for the whole expanded script, including
     * same-IP controls. The short fingerprint is an identity check, not
     * an authentication mechanism. */
    fun preparationValid(plan: DptsPlan, prepared: Zapret2GoogleProbe): Boolean =
        plan.probes.isNotEmpty() && prepared.outcome == "dns_ready" &&
            prepared.dnsAnswers in 1..8 && prepared.dnsFingerprint.matches(Regex("[0-9a-f]{8}")) &&
            plan.probes.all { it.ipIndex in 0 until prepared.dnsAnswers }

    fun rowMatchesPreparation(spec: DptsProbe, row: Zapret2GoogleAttempt,
        prepared: Zapret2GoogleProbe): Boolean =
        spec.matches(row) && row.result.dnsFingerprint == prepared.dnsFingerprint &&
            row.result.dnsAnswers == prepared.dnsAnswers

    fun completeEvidence(plan: DptsPlan, prepared: Zapret2GoogleProbe,
        rows: List<Zapret2GoogleAttempt>): Boolean =
        preparationValid(plan, prepared) && rows.size == plan.probes.size &&
            plan.probes.indices.all { rowMatchesPreparation(plan.probes[it], rows[it], prepared) }

    /** Caller never includes HTTP response bytes, raw IPs, credentials or URLs. */
    fun report(plan: DptsPlan, network: String, prepared: Zapret2GoogleProbe,
        observations: List<Zapret2GoogleAttempt>): String = buildString {
        appendLine("=== DPpass — DPTS/1 ===")
        appendLine("Название: ${plan.title}")
        appendLine("Сеть: $network; host=${plan.host}")
        appendLine("DoH: ${prepared.outcome}; IPv4=${prepared.dnsAnswers};" +
            " fingerprint=${prepared.dnsFingerprint}")
        val preparationValid = preparationValid(plan, prepared)
        val matched = plan.probes.indices.mapNotNull { i ->
            val row = observations.getOrNull(i) ?: return@mapNotNull null
            if (preparationValid && rowMatchesPreparation(plan.probes[i], row, prepared))
                i to row.result else null
        }.toMap()
        appendLine("Выполнено: ${observations.size}/${plan.probes.size};" +
            " worst_case_budget_ms=${plan.budgetMs}")
        appendLine("matched_rows=${matched.size}; unbound_rows=${observations.size - matched.size};" +
            " missing_rows=${(plan.probes.size - observations.size).coerceAtLeast(0)};" +
            " extra_rows=${(observations.size - plan.probes.size).coerceAtLeast(0)}")
        appendLine("dns_preparation_valid=$preparationValid; complete_evidence=" +
            completeEvidence(plan, prepared, observations))
        for (phase in plan.probes.map { it.phase }.distinct()) {
            val indices = plan.probes.indices.filter { plan.probes[it].phase == phase }
            val results = indices.mapNotNull { i -> matched[i]?.let { plan.probes[i] to it } }
            val verified = results.count { (spec, r) -> spec.handshakeVerified(r) }
            val transport = results.count { (spec, r) ->
                spec.handshakeVerified(r) && (spec.wireProtocol == "quic" || r.httpStatus in 200..499)
            }
            val bounded = results.count { (spec, r) ->
                spec.boundedHttpsSuccess(r) && plan.host != Zapret2SiteSearch.YOUTUBE_API_HOST
            }
            // The native verifier checks HTML for the fixed YouTube home
            // and JPEG for the fixed thumbnail. Generic site_http checks
            // only bounded 2xx bytes, not the type or application content.
            val content = if (plan.host in setOf("www.youtube.com", "i.ytimg.com")) bounded else 0
            val planned = indices.size
            appendLine("  phase=$phase: transport=$transport/$planned;" +
                " tls_verified=$verified/$planned;" +
                " bounded_http_success=$bounded/$planned;" +
                " content_verified=$content/$planned;" +
                " matched=${results.size}/$planned")
        }
        for ((i, row) in observations.withIndex()) {
            val spec = plan.probes.getOrNull(i) ?: break
            val r = row.result
            val binding = if (i in matched) "matched" else "unbound"
            appendLine("  step=$i phase=${spec.phase} ip_index=${spec.ipIndex}" +
                " method=${spec.method} protocol=${spec.protocol}" +
                " attempt=${spec.attempt} binding=$binding outcome=${r.outcome}" +
                " tls_stage=${r.tlsStage} alpn=${r.alpn}" +
                " http=${r.httpStatus} body_bytes_bounded=${r.bodyBytes}" +
                " elapsed_ms=${r.elapsedMillis}")
        }
        appendLine(if (plan.observeLearning)
            "LEARNING: observations_exported_only; model_weights_unchanged." else
            "LEARNING: disabled.")
        appendLine("AUTO: not_applied; DNS/routes/QUIC/VPN profile unchanged.")
        appendLine("3xx/4xx HTTP proves transport only; TLS/QUIC does not prove API POST or video.")
        appendLine("IP addresses, private paths, cookies, certificates and response bodies not exported.")
    }
}

/** Immutable editable text presets. No downloaded/executable code is loaded. */
object DptsPresets {
    val scripts: Map<String, String> = linkedMapOf(
        "Полный тест Google/YouTube (старый)" to """
            dpts 1
            name Google YouTube all fixed controls
            host www.google.com
            suite google_youtube
        """.trimIndent(),
        "Сравнение защищённых DNS" to """
            dpts 1
            name DoH comparison across providers
            host youtubei.googleapis.com
            suite dns_compare
        """.trimIndent(),
        "Матрица IPv4 / TLS / HTTP2 / QUIC" to """
            dpts 1
            name Protected transport matrix
            host youtubei.googleapis.com
            suite ip_matrix
        """.trimIndent(),
        "YouTube API · расширенный HTTP3" to """
            dpts 1
            name HTTP3 API controls and Google pre-post checks
            host youtubei.googleapis.com
            suite h3_api
        """.trimIndent(),
        "Поиск стратегий · HTTPS" to """
            dpts 1
            name Search all HTTPS methods on specified public host
            host www.youtube.com
            suite site_https
        """.trimIndent(),
        "Поиск стратегий · QUIC" to """
            dpts 1
            name Search QUIC methods on specified public host
            host www.youtube.com
            suite site_quic
        """.trimIndent(),
        "API · 8 IP, полная старая методика" to """
            dpts 1
            name Original eight-IP H1 H2 sweep and confirmations
            host youtubei.googleapis.com
            suite api_ipv4_sweep
        """.trimIndent(),
        "API · SNI, полная старая методика" to """
            dpts 1
            name Original same-IP SNI controls and confirmations
            host youtubei.googleapis.com
            suite sni_control
        """.trimIndent(),
        "API · TLS-версии, полная старая методика" to """
            dpts 1
            name Original TLS version paired controls
            host youtubei.googleapis.com
            suite tls_versions
        """.trimIndent(),
        "YouTube API · 8 IPv4 H1/H2" to """
            dpts 1
            name API IPv4 H1-H2 differential
            host youtubei.googleapis.com
            learn observe
            https protocols=h1,h2 methods=plain,tlsrec-split ips=8 attempts=1 timeout_ms=5000
        """.trimIndent(),
        "YouTube API · SNI on same IP" to """
            dpts 1
            name API vs Google same-IP SNI
            host youtubei.googleapis.com
            sni ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "YouTube API · TLS 1.2 / 1.3" to """
            dpts 1
            name API vs Google TLS1.2 TLS1.3
            host youtubei.googleapis.com
            tls versions=12,13 methods=plain compare_google=true ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "YouTube API · all TCP methods" to """
            dpts 1
            name Full seven-method YouTube API HTTPS scan
            host youtubei.googleapis.com
            learn observe
            https protocols=h1 methods=plain,split-1,split,tlsrec-split,fake-3,fake-5,disorder ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "YouTube API · дополнительные TCP профили" to """
            dpts 1
            name Extended native TCP profile comparison
            host youtubei.googleapis.com
            https protocols=h1,h2 methods=plain,split-2,fake-2,fake-4,fake-8 ips=2 attempts=2 timeout_ms=5000
        """.trimIndent(),
        "YouTube · public thumbnail" to """
            dpts 1
            name Fixed public thumbnail JPEG
            host i.ytimg.com
            https protocols=h1 methods=plain,tlsrec-split,fake-5 ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "YouTube · homepage" to """
            dpts 1
            name YouTube homepage verified HTTPS
            host www.youtube.com
            learn observe
            https protocols=h1,h2 methods=plain,tlsrec-split ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "YouTube API · QUIC handshake" to """
            dpts 1
            name YouTube API QUIC transport only
            host youtubei.googleapis.com
            quic methods=plain,fake-3,fake-5 ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
        "Google · baseline" to """
            dpts 1
            name Google baseline without DPI changes
            host www.google.com
            https protocols=h1,h2 methods=plain ips=2 attempts=3 timeout_ms=5000
        """.trimIndent(),
    )
}
