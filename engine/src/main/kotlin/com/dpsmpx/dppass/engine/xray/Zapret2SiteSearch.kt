package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import java.net.IDN
import java.util.Locale

/**
 * One explicit, on-device, bounded strategy search for a user-entered HTTPS
 * hostname. Transport observations are not evidence that a protected app,
 * video or authenticated website works. Hostnames and results are never
 * persisted; only the private native AUTO selector may receive a vetted
 * exact-host recommendation after the user requests application.
 */
object Zapret2SiteSearch {
    const val ATTEMPTS = 3
    const val MAX_IPS = 2
    const val MAX_SWEEP_IPS = 8
    const val YOUTUBE_API_HOST = "youtubei.googleapis.com"
    // Fast one-attempt, all-IP diagnostics. H2 varies TLS ALPN while
    // preserving SNI, certificate validation, hostname and test outbounds.
    val apiSweepProfiles = listOf(
        "h1" to "plain", "h1" to "tlsrec-split",
        "h2" to "plain", "h2" to "tlsrec-split", "h2" to "fake-5",
    )
    const val TTL_MS = 5 * 60 * 1000L
    val tcpMethods = Zapret2ProbeCatalog.siteTcpMethods
    val quicMethods = Zapret2ProbeCatalog.siteQuicMethods
    val methodLabels = mapOf(
        "plain" to "Без изменений / контроль",
        "split-1" to "TCP split: 1 байт",
        "split" to "TCP split в имени SNI",
        "tlsrec-split" to "TLS record split + TCP split",
        "fake-3" to "TTL 3: fake + TCP split (или QUIC Initial)",
        "fake-5" to "TTL 5: fake + TCP split (или QUIC Initial)",
        "disorder" to "TCP disorder / low TTL"
    )

    /** DNS names only: never accept a URL, credentials, port or raw IP. */
    fun normalizedHost(value: String): String? {
        val trimmed = value.trim().trimEnd('.')
        if (trimmed.isEmpty() || trimmed.length > 253 ||
            trimmed.any { it.isWhitespace() || it in ":/@?#%" || it == '\\' }) return null
        val ascii = try {
            IDN.toASCII(trimmed, IDN.USE_STD3_ASCII_RULES).lowercase(Locale.ROOT)
        } catch (_: IllegalArgumentException) { return null }
        if (ascii.length !in 4..253 || !ascii.contains('.')) return null
        val labels = ascii.split('.')
        if (labels.any { it.length !in 1..63 || !it.matches(
                Regex("[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")) }) return null
        val tld = labels.last()
        val publicTld = if (tld.startsWith("xn--")) tld.length >= 6
            else tld.length >= 2 && tld.all { it in 'a'..'z' }
        if (!publicTld ||
            tld in setOf("local", "localhost", "internal", "lan", "home",
                "test", "invalid", "example", "onion", "arpa")) return null
        return ascii
    }

    fun prepare(host: String) = "site_prepare:$host"
    fun apply(host: String) = "site_apply:$host"
    fun trial(host: String, ipIndex: Int, attempt: Int, quic: Boolean): String {
        require(ipIndex in 0 until MAX_IPS && attempt in 1..ATTEMPTS)
        return (if (quic) "site_quic_ip" else "site_ip") +
            ipIndex.toString().padStart(2, '0') + "_a" + attempt + "_:" + host
    }

    fun apiSweepTrial(index: Int, attempt: Int, protocol: String): String {
        require(index in 0 until MAX_SWEEP_IPS && attempt in 1..ATTEMPTS)
        require(protocol == "h1" || protocol == "h2")
        return "site_sweep_${protocol}_ip" + index.toString().padStart(2, '0') +
            "_a${attempt}_:${YOUTUBE_API_HOST}"
    }

    /** All-IP samples are diagnostic-only, never eligible for an AUTO commit. */
    fun apiSweepReport(
        network: String, prepared: Zapret2GoogleProbe,
        rows: List<Zapret2GoogleAttempt>, ipCount: Int,
    ): String = buildString {
        appendLine("=== DPpass — YouTube API, 8 IPv4 / HTTPS H1-H2 ===")
        appendLine("Сеть: $network; цель: $YOUTUBE_API_HOST")
        appendLine("DoH: ${prepared.outcome}; IPv4=${prepared.dnsAnswers}; fingerprint=${prepared.dnsFingerprint}")
        appendLine("Проверены $ipCount IPv4, максимум 5 профилей на IP. Основной проход: 1 соединение на профиль.")
        appendLine("Дополнительные повторы выполняются максимум для двух успешных профилей/IP; это не AUTO.")
        for ((proto, method) in apiSweepProfiles) {
            val group = rows.filter { it.strategy == method && it.result.protocol == proto }
            val tls = group.count { it.result.tlsStage == "tls_verified" &&
                it.result.alpn == (if (proto == "h2") "h2" else "http/1.1") }
            val http = group.count {
                it.result.tlsStage == "tls_verified" && it.result.httpStatus in 200..499 &&
                it.result.outcome in setOf("http_reachable", "ok", "redirect")
            }
            appendLine("  $proto / $method: TLS $tls/${group.size}, HTTP $http/${group.size}")
        }
        for (row in rows) {
            val r = row.result
            appendLine("  ip_index=${r.ipIndex} protocol=${r.protocol} method=${row.strategy}" +
                " attempt=${row.attempt} outcome=${r.outcome}" +
                " stage=${r.tlsStage} alpn=${r.alpn} http=${r.httpStatus}" +
                " elapsed_ms=${r.elapsedMillis}")
        }
        val anyHTTP = rows.any { it.result.tlsStage == "tls_verified" &&
            it.result.httpStatus in 200..499 }
        appendLine(if (anyHTTP)
            "Итог: получен хотя бы один HTTPS-ответ. Разовые успехи требуют повторения и не доказывают работу ленты."
            else
            "Итог: ни один проверенный профиль/IP не вернул HTTP-ответ. Это не доказывает причину отказа.")
        appendLine("AUTO: not_applied (диагностика; не влияет на маршрут или обучение).")
        appendLine("HTTP/2 TLS/ALPN — не доказательство API POST, авторизации или видео.")
        appendLine("Результаты не содержат IP-адресов, URL-путей, тел, ключей или cookies.")
    }


    /**
     * Fixed SNI differential on the same eight API A addresses.
     * The peer still uses the original certificate-verified host identity
     * and this request can never feed the native AUTO selector.
     */
    fun sameIpControlTrial(index: Int, attempt: Int): String {
        require(index in 0 until MAX_SWEEP_IPS && attempt in 1..ATTEMPTS)
        return "site_sni_google_ip" + index.toString().padStart(2, '0') +
            "_a${attempt}_:${YOUTUBE_API_HOST}"
    }

    private fun tlsReached(row: Zapret2GoogleAttempt): Boolean =
        row.result.tlsStage == "tls_verified" &&
            row.result.alpn == "http/1.1" &&
            row.result.httpStatus in 200..499 &&
            row.result.outcome in setOf("ok", "http_reachable", "redirect")

    fun sameIpControlReport(
        network: String, prepared: Zapret2GoogleProbe,
        ownControl: Zapret2GoogleProbe?, ownPrepared: Zapret2GoogleProbe?,
        rows: List<Zapret2GoogleAttempt>, ipCount: Int,
    ): String = buildString {
        appendLine("=== DPpass — TLS/SNI контроль на тех же IP YouTube API ===")
        appendLine("Сеть: $network; API: $YOUTUBE_API_HOST; контроль: www.google.com")
        appendLine("DoH API: ${prepared.outcome}; IPv4=${prepared.dnsAnswers}; fingerprint=${prepared.dnsFingerprint}")
        appendLine("Независимый Google DoH контроль: ${ownPrepared?.outcome ?: "not_run"};" +
            " TLS=${ownControl?.tlsStage ?: "-"}; HTTP=${ownControl?.httpStatus ?: 0};" +
            " outcome=${ownControl?.outcome ?: "not_run"}")
        appendLine("Проверены $ipCount IP API из одного A-набора с разными SNI/Host;" +
            " сертификат проверяется для каждого имени.")
        var controlGood = 0
        var apiGood = 0
        var matched = 0
        for (ip in 0 until ipCount) {
            val api = rows.filter {
                it.result.ipIndex == ip && it.target.startsWith("site_sweep_h1_ip") &&
                    it.strategy == "plain" }
            val control = rows.filter {
                it.result.ipIndex == ip && it.target.startsWith("site_sni_google_ip") &&
                    it.strategy == "plain" }
            val apiOk = api.count(::tlsReached)
            val controlOk = control.count(::tlsReached)
            if (apiOk > 0) apiGood++
            if (controlOk > 0) controlGood++
            if (api.isNotEmpty() && control.isNotEmpty()) matched++
            appendLine("  ip_index=$ip API TLS/HTTP=$apiOk/${api.size};" +
                " Google same-IP TLS/HTTP=$controlOk/${control.size};" +
                " Google 3/3=${control.size == ATTEMPTS && controlOk == ATTEMPTS}")
        }
        for (row in rows) {
            val r = row.result
            val identity = if (row.target.startsWith("site_sni_google_ip"))
                "google_control" else "youtube_api"
            appendLine("  ip_index=${r.ipIndex} sni=$identity attempt=${row.attempt}" +
                " outcome=${r.outcome} stage=${r.tlsStage} alpn=${r.alpn}" +
                " http=${r.httpStatus} elapsed_ms=${r.elapsedMillis}")
        }
        appendLine("Итог: API дал HTTP-ответ хотя бы на одном IP: ${apiGood>0};" +
            " контроль www.google.com ответил на ${controlGood}/$matched IP.")
        val stableSniContrast = (0 until ipCount).any { ip ->
            val api = rows.filter { it.result.ipIndex == ip &&
                it.target.startsWith("site_sweep_h1_ip") }
            val google = rows.filter { it.result.ipIndex == ip &&
                it.target.startsWith("site_sni_google_ip") }
            api.size == ATTEMPTS && google.size == ATTEMPTS &&
                api.none(::tlsReached) && google.all(::tlsReached)
        }
        if (stableSniContrast) {
            appendLine("Стабильный Google TLS на том же IP при отсутствии API TLS" +
                " поддерживает гипотезу зависимости от SNI, но не доказывает DPI.")
        } else {
            appendLine("Отсутствие ответа Google на IP API не исключает блокировку SNI:" +
                " один IP может не обслуживать это имя.")
        }
        appendLine("AUTO: not_applied. Контроль ничего не переключает и не обучает.")
        appendLine("Сравнение SNI не подтверждает работу YouTube API POST/ленты/видео.")
        appendLine("IP, пути, тела ответов, сертификаты и ключи не экспортируются.")
    }


    /** Two IPv4 addresses, 2 TLS versions, 2 certificate-verified SNI names. */
    fun tlsVersionTrial(index: Int, attempt: Int, version: Int,
        google: Boolean): String {
        require(index in 0 until MAX_IPS && attempt in 1..ATTEMPTS)
        require(version == 12 || version == 13)
        return "site_tls${version}_" + (if (google) "google" else "api") +
            "_ip" + index.toString().padStart(2, '0') +
            "_a${attempt}_:${YOUTUBE_API_HOST}"
    }

    fun tlsVersionReport(network: String, prepared: Zapret2GoogleProbe,
        rows: List<Zapret2GoogleAttempt>, ipCount: Int): String = buildString {
        appendLine("=== DPpass — сравнение TLS 1.2 и TLS 1.3 на IP YouTube API ===")
        appendLine("Сеть: $network; DoH: ${prepared.outcome}; IPv4=${prepared.dnsAnswers};" +
            " fingerprint=${prepared.dnsFingerprint}")
        appendLine("Протокол: HTTPS HTTP/1.1, plain, проверка сертификата и исходного SNI.")
        for (ip in 0 until ipCount) for (v in listOf(12, 13)) {
            val apiPrefix = "site_tls${v}_api_ip"
            val googlePrefix = "site_tls${v}_google_ip"
            val api = rows.filter {
                it.result.ipIndex == ip && it.target.startsWith(apiPrefix) }
            val google = rows.filter {
                it.result.ipIndex == ip && it.target.startsWith(googlePrefix) }
            val a = api.count(::tlsReached)
            val g = google.count(::tlsReached)
            appendLine("  ip_index=$ip TLS1.${v % 10}: API TLS/HTTP=$a/${api.size};" +
                " Google TLS/HTTP=$g/${google.size}")
            if (api.size == ATTEMPTS && google.size == ATTEMPTS &&
                a == 0 && g == ATTEMPTS) {
                appendLine("  Стабильное различие по имени TLS на одном IP" +
                    " при TLS 1.${v % 10}, но причина не установлена.")
            }
        }
        for (row in rows) {
            val r = row.result
            val version = if (row.target.startsWith("site_tls12_")) "1.2" else "1.3"
            val hostKind = if (row.target.contains("_google_ip")) "google" else "api"
            appendLine("  ip_index=${r.ipIndex} tls=$version sni=$hostKind" +
                " attempt=${row.attempt} outcome=${r.outcome}" +
                " stage=${r.tlsStage} alpn=${r.alpn} http=${r.httpStatus}" +
                " elapsed_ms=${r.elapsedMillis}")
        }
        appendLine("AUTO: not_applied. Это только диагностика.")
        appendLine("TLS-успех не подтверждает работу авторизованного API, ленты или видео.")
        appendLine("Не экспортируются IP, приватные пути, тела, ключи и сертификаты.")
    }

    data class Candidate(
        val method: String,
        val verified: Int,
        val attempted: Int,
        val meanLatency: Long?,
        val stable: Boolean,
        // 3xx redirects and expected 4xx API/CDN root replies prove
        // authenticated TLS+HTTP reachability, not usable app content.
        val transportVerified: Int = 0,
        val transportStable: Boolean = false,
    )
    data class Recommendation(
        val method: String?,
        val baselineStable: Boolean,
        val label: String,
        val candidates: List<Candidate>,
        val readyToApply: Boolean,
    )

    fun recommend(
        host: String,
        count: Int,
        rows: List<Zapret2GoogleAttempt>,
        quic: Boolean,
    ): Recommendation {
        val methods = if (quic) quicMethods else tcpMethods
        val ips = count.coerceIn(0, MAX_IPS)
        val rank = methods.map { method ->
            var successes = 0
            var transport = 0
            var total = 0
            var latency = 0L
            var allCompleteAndStable = ips > 0
            var allCompleteAndTransport = ips > 0
            for (ip in 0 until ips) {
                val expected = (1..ATTEMPTS).map { number ->
                    val target = trial(host, ip, number, quic)
                    rows.filter { it.strategy == method &&
                        it.target == target && it.attempt == number }
                }
                if (expected.any { it.size != 1 }) {
                    allCompleteAndStable = false
                    allCompleteAndTransport = false
                }
                for (matched in expected) {
                    val row = matched.singleOrNull() ?: continue
                    total++
                    val actual = row.result
                    val verified = if (quic) actual.protocol == "quic" &&
                        actual.outcome == "quic_verified" &&
                        actual.tlsStage == "quic_tls_verified" && actual.alpn == "h3"
                    else actual.protocol == "h1" &&
                        actual.outcome == "ok" && actual.httpStatus in 200..299 &&
                        actual.bodyBytes >= 128 && actual.tlsStage == "tls_verified"
                    // A 301 redirect or 404 at GET / is a real server
                    // response, not a DPI failure. It must not be treated
                    // as verified content nor train a desync preference.
                    val reachable = if (quic) verified else
                        actual.protocol == "h1" &&
                        actual.tlsStage == "tls_verified" &&
                        actual.alpn == "http/1.1" &&
                        actual.httpStatus in 200..499 &&
                        actual.outcome in setOf("ok", "http_reachable", "redirect")
                    if (reachable) transport++ else allCompleteAndTransport = false
                    if (verified) {
                        successes++
                        latency += actual.elapsedMillis
                    } else allCompleteAndStable = false
                }
            }
            Candidate(method, successes, total,
                if (successes > 0) latency / successes else null,
                allCompleteAndStable && successes == ips * ATTEMPTS,
                transportVerified = transport,
                transportStable = allCompleteAndTransport &&
                    transport == ips * ATTEMPTS)
        }
        val baseline = rank.first()
        if (ips == 0) return Recommendation(null, false,
            "Нет проверенного публичного IPv4 или истёк срок DNS. Рекомендация недоступна.",
            rank, false)
        if (baseline.stable) return Recommendation("plain", true,
            "Исходный маршрут устойчив на всех проверенных IPv4. Изменение стратегии не требуется.",
            rank, false)
        if (!quic && baseline.transportStable) return Recommendation("plain", false,
            "Обычный HTTPS без модификации получает HTTP-ответы на каждом IP. " +
                "Ответы 301/404 подтверждают транспорт, но не полезный контент; " +
                "AUTO не изменён и DPI-метод не нужен для этого запроса.",
            rank, false)
        // No promotion if the baseline sometimes works 2/3 at any index.
        val baselineFailuresEnough = (0 until ips).all { ip ->
            (1..ATTEMPTS).count { number ->
                rows.singleOrNull { it.strategy == "plain" &&
                    it.target == trial(host, ip, number, quic) &&
                    it.attempt == number }?.result?.let { result ->
                    if (quic) result.outcome == "quic_verified" &&
                        result.tlsStage == "quic_tls_verified" && result.alpn == "h3"
                    else result.outcome == "ok" &&
                        result.httpStatus in 200..299 &&
                        result.bodyBytes >= 128 && result.tlsStage == "tls_verified"
                } == true
            } <= 1 &&
            (1..ATTEMPTS).all { number ->
                rows.count { it.strategy == "plain" &&
                    it.target == trial(host, ip, number, quic) &&
                    it.attempt == number } == 1
            }
        }
        val finalists = rank.drop(1).filter { it.stable }
        if (!baselineFailuresEnough || finalists.isEmpty()) return Recommendation(
            null, false, "Надёжный победитель не подтверждён. " +
                "Разовые ответы, TLS-handshake и 2/3 попытки не считаются достаточными.",
            rank, false)
        val best = finalists.minWithOrNull(
            compareBy<Candidate>({ it.meanLatency ?: Long.MAX_VALUE },
                { methods.indexOf(it.method) }))!!
        return Recommendation(best.method, false,
            if (quic)
                "Подтверждены 3/3 QUIC TLS/ALPN на каждом IP; это только транспорт, не видео или HTTP/3."
            else
                "Подтверждены 3/3 HTTPS-ответов на каждом IP с проверкой сертификата и тела.",
            rank, !quic)
    }

    /** A report is explicitly copied by the user; private IPs never appear. */
    fun report(host: String, network: String, quic: Boolean,
        prepared: Zapret2GoogleProbe, rows: List<Zapret2GoogleAttempt>,
        recommendation: Recommendation, commit: Zapret2GoogleProbe? = null): String =
        buildString {
            appendLine("=== DPpass — автоматический поиск стратегий ===")
            appendLine("Сайт по запросу пользователя: $host")
            appendLine("Сеть: $network")
            appendLine("Протокол: " + (if (quic) "QUIC v1 / TLS 1.3 / ALPN h3" else "HTTPS / TLS / HTTP1.1"))
            appendLine("DoH: ${prepared.outcome}; IPv4=${prepared.dnsAnswers}; fingerprint=${prepared.dnsFingerprint}")
            appendLine("Проверены максимум 2 IPv4, по 3 независимых соединения на метод; не меняем глобальные DNS/маршруты.")
            for (candidate in recommendation.candidates) {
                appendLine("  ${candidate.method}: ${candidate.verified}/${candidate.attempted}" +
                    " content_verified; stable=${candidate.stable};" +
                    (if (quic) "" else
                        " http_transport=${candidate.transportVerified}/${candidate.attempted};" +
                        " transport_stable=${candidate.transportStable};") +
                    " mean_success_ms=${candidate.meanLatency ?: "-"}")
            }
            appendLine("Точные результаты (без адресов, доменных токенов и содержимого):")
            for (entry in rows) {
                val r = entry.result
                appendLine("  ip_index=${r.ipIndex} method=${entry.strategy}" +
                    " attempt=${entry.attempt} outcome=${r.outcome}" +
                    " stage=${r.tlsStage} alpn=${r.alpn}" +
                    " http=${r.httpStatus} body_bytes_bounded=${r.bodyBytes}" +
                    " elapsed_ms=${r.elapsedMillis}")
            }
            appendLine("Выбор: ${recommendation.method ?: "-"} — ${recommendation.label}")
            appendLine("AUTO: ${commit?.outcome ?: "not_applied"}")
            if (!quic && commit?.outcome == "auto_applied" &&
                recommendation.method != null && recommendation.method != "plain") {
                val fallback = recommendation.candidates.filter {
                    it.stable && it.method != "plain" && it.method != recommendation.method
                }.minWithOrNull(compareBy<Candidate>({ it.meanLatency ?: Long.MAX_VALUE },
                    { tcpMethods.indexOf(it.method) }))
                appendLine("Резерв для AUTO при подтверждённых тайм-аутах: " +
                    (fallback?.method ?: "-") +
                    " (только другой 3/3 HTTPS-кандидат того же домена).")
            }
            appendLine("QUIC TLS — не доказательство HTTP/3 GET, работы API или воспроизведения.")
            appendLine("HTTPS 2xx с небольшим телом — не доказательство авторизации или работы всего сайта.")
            appendLine("Другие IP/CDN/поддомены/протоколы не проверялись.")
            appendLine("Результаты не включают raw IP, тела, cookie, URL-пути, ключи или сертификаты.")
        }
}
