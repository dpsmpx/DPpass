package com.dpsmpx.dppass.engine.xray

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
    const val TTL_MS = 5 * 60 * 1000L
    val tcpMethods = listOf(
        "plain", "split-1", "split", "tlsrec-split", "fake-3", "fake-5", "disorder"
    )
    val quicMethods = listOf("plain", "fake-3", "fake-5")
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
        if (tld.length < 2 || !tld.all { it in 'a'..'z' } ||
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

    data class Candidate(
        val method: String,
        val verified: Int,
        val attempted: Int,
        val meanLatency: Long?,
        val stable: Boolean,
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
            var total = 0
            var latency = 0L
            var allCompleteAndStable = ips > 0
            for (ip in 0 until ips) {
                val expected = (1..ATTEMPTS).map { number ->
                    val target = trial(host, ip, number, quic)
                    rows.filter { it.strategy == method &&
                        it.target == target && it.attempt == number }
                }
                if (expected.any { it.size != 1 }) allCompleteAndStable = false
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
                    if (verified) {
                        successes++
                        latency += actual.elapsedMillis
                    } else allCompleteAndStable = false
                }
            }
            Candidate(method, successes, total,
                if (successes > 0) latency / successes else null,
                allCompleteAndStable && successes == ips * ATTEMPTS)
        }
        val baseline = rank.first()
        if (ips == 0) return Recommendation(null, false,
            "Нет проверенного публичного IPv4 или истёк срок DNS. Рекомендация недоступна.",
            rank, false)
        if (baseline.stable) return Recommendation("plain", true,
            "Исходный маршрут устойчив на всех проверенных IPv4. Изменение стратегии не требуется.",
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
                    " successful; stable=${candidate.stable}; mean_success_ms=${candidate.meanLatency ?: "-"}")
            }
            appendLine("Выбор: ${recommendation.method ?: "-"} — ${recommendation.label}")
            if (commit != null) appendLine("AUTO: ${commit.outcome}")
            appendLine("QUIC TLS — не доказательство HTTP/3 GET, работы API или воспроизведения.")
            appendLine("HTTPS 2xx с небольшим телом — не доказательство авторизации или работы всего сайта.")
            appendLine("Другие IP/CDN/поддомены/протоколы не проверялись.")
            appendLine("Результаты не включают raw IP, тела, cookie, URL-пути, ключи или сертификаты.")
        }
}
