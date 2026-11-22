package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog

/** Bounded v1 native HTTPS probe response; no payloads or URL input. */
data class Zapret2GoogleProbe(
    val outcome: String,
    val httpStatus: Int,
    val bodyBytes: Long,
    val elapsedMillis: Long,
    val appliedDelta: Long,
    val skippedDelta: Long,
) {
    /** An HTTP 3xx proves reachability, not final content. */
    val success: Boolean get() = outcome == "ok"
    /** Only proof of a TLS-verified HTTP reply, not authorized API content. */
    val httpReachable: Boolean get() = success || outcome == "http_reachable"

    companion object {
        val outcomes: Set<String> = setOf(
            "ok", "redirect", "engine_off", "invalid_strategy", "invalid_timeout",
            "dial_failed", "timeout", "tls_failed", "tls_ca_failed",
            "request_failed", "http_failed", "http_status", "body_failed",
            "empty_body", "content_type_mismatch", "content_invalid", "http_reachable",
            "invalid_target", "unsupported", "contract_error",
        )
        fun unavailable(): Zapret2GoogleProbe =
            Zapret2GoogleProbe("contract_error", 0, 0, 0, 0, 0)

        fun fromWire(bytes: ByteArray): Zapret2GoogleProbe {
            val fields = bytes.decodeToString().split('\t')
            if (fields.size != 7 || fields[0] != "v1" || fields[1] !in outcomes) return unavailable()
            val http = fields[2].toIntOrNull()?.takeIf { it in 0..599 } ?: return unavailable()
            val numbers = fields.drop(3).map { it.toLongOrNull()?.takeIf { value -> value >= 0 } ?: return unavailable() }
            return Zapret2GoogleProbe(fields[1], http, numbers[0], numbers[1], numbers[2], numbers[3])
        }
    }
}

data class Zapret2GoogleAttempt(
    val strategy: String,
    val attempt: Int,
    val result: Zapret2GoogleProbe,
    val target: String = "google_final",
)

/** Complete plaintext report for clipboard; all attempts, including failures. */
object Zapret2GoogleReport {
    /**
     * A provisional exact-host hint, never a global or permanent ranking.
     * Require two baseline failures and two verified 200+HTML bodies for
     * the same manual TCP strategy. Do not infer from 301, Google or JPEG.
     */
    fun provisionalYouTubeHint(attempts: List<Zapret2GoogleAttempt>): String? =
        provisionalHint(attempts, "youtube_home") { it.success }

    /**
     * Provisional API *transport* only. Even HTTP 403/404 may establish
     * verified HTTPS routing, but never authorizes or proves feed content.
     */
    fun provisionalAPITransportHint(attempts: List<Zapret2GoogleAttempt>): String? =
        provisionalHint(attempts, "youtube_api_transport") { it.httpReachable }

    private fun provisionalHint(
        attempts: List<Zapret2GoogleAttempt>,
        target: String,
        reached: (Zapret2GoogleProbe) -> Boolean,
    ): String? {
        val rows = attempts.filter { it.target == target }
        val plain = rows.filter { it.strategy == "plain" }
        if (plain.size != 2 || !plain.all {
                it.result.outcome in setOf("timeout", "dial_failed", "tls_failed")
            }) return null
        return Zapret2ProbeCatalog.strategies.filter { it != "auto" && it != "plain" }
            .mapNotNull { strategy ->
                val attemptsForMode = rows.filter { it.strategy == strategy }
                if (attemptsForMode.size == 2 && attemptsForMode.all { reached(it.result) }) {
                    strategy to attemptsForMode.sumOf { it.result.elapsedMillis }
                } else null
            }.minByOrNull { it.second }?.first
    }

    /** Exact median in milliseconds, preserving .5 for even sample counts. */
    fun medianMillis(values: List<Long>): String {
        if (values.isEmpty()) return "-"
        val sorted = values.sorted()
        val left = sorted[(sorted.size - 1) / 2]
        val right = sorted[sorted.size / 2]
        // Native attempts are bounded by a few seconds; the sum fits in Long.
        val sum = left + right
        return if (sum % 2L == 0L) (sum / 2L).toString() else "${sum / 2L}.5"
    }

    fun render(
        timestamp: String,
        network: String,
        quicForceTcp: Boolean,
        attempts: List<Zapret2GoogleAttempt>,
    ): String = buildString {
        appendLine("=== DPpass — Zapret2 multi-site HTTPS autotest ===")
        appendLine("Time: $timestamp")
        appendLine("Network: $network")
        appendLine("Mode: active experimental VpnService; AUTO primary; QUIC->TCP=$quicForceTcp")
        appendLine("Transport: TLS certificate verified, direct GET / GET JPEG, max 8 KiB")
        appendLine("Targets: google_final=www.google.com/ (HTML); " +
            "youtube_home=www.youtube.com/ (HTML); " +
            "youtube_api_transport=youtubei.googleapis.com/youtubei/v1/browse (TLS+HTTP only); " +
            "youtube_thumbnail=i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg (JPEG)")
        appendLine("API transport: HTTP 2xx/4xx may prove TLS and HTTP reachability, not usable YouTube API or feed.")
        appendLine("Redirects are NOT followed; a redirect is not a verified content success.")
        appendLine("HTTP 200 alone is not success: HTML/JPEG signatures checked.")
        appendLine("Scope: TCP/HTTPS only; QUIC, YouTube app API and video streaming NOT tested.")
        appendLine("Strategies: ${Zapret2ProbeCatalog.strategies.joinToString(", ")}")
        appendLine("Targets count: ${Zapret2ProbeCatalog.targets.size}; attempts: ${attempts.size}")
        appendLine()
        appendLine("Summary by target:")
        for (target in Zapret2ProbeCatalog.targets) {
            appendLine("TARGET $target — ${Zapret2ProbeCatalog.targetLabel(target)}")
            for (strategy in Zapret2ProbeCatalog.strategies) {
                val rows = attempts.filter { it.target == target && it.strategy == strategy }
                val transport = target == "youtube_api_transport"
                val ok = rows.count { if (transport) it.result.httpReachable else it.result.success }
                val median = medianMillis(rows.filter { if (transport) it.result.httpReachable else it.result.success }
                    .map { it.result.elapsedMillis })
                val outcomes = rows.map { it.result.outcome }.joinToString(",").ifEmpty { "not_run" }
                val unit = if (transport) "HTTP transport (not API content)" else "content"
                appendLine("  $strategy: $ok/${rows.size} $unit; median_ok_ms=$median; outcomes=$outcomes")
            }
        }
        appendLine()
        appendLine("Every attempt:")
        attempts.forEachIndexed { index, a ->
            val r = a.result
            appendLine("${index + 1}. target=${a.target} strategy=${a.strategy} #${a.attempt}: " +
                "outcome=${r.outcome} http=${r.httpStatus} body_bytes=${r.bodyBytes} " +
                "elapsed_ms=${r.elapsedMillis} applied_delta=${r.appliedDelta} skipped_delta=${r.skippedDelta}")
        }
        appendLine()
        appendLine("All modes run through private test outbounds; ordinary VPN strategy is unchanged.")
        appendLine("Applied/skipped counters are process-wide and may include unrelated apps.")
        appendLine("A Google reply does NOT prove YouTube works; a YouTube HTML/thumbnail " +
            "reply does NOT prove the app API or video streams work.")
        appendLine("i.ytimg.com is thumbnail CDN, NOT the googlevideo.com media stream.")
        val hint = provisionalYouTubeHint(attempts)
        if (hint != null) {
            appendLine("Provisional exact-host AUTO candidate: $hint for www.youtube.com")
            appendLine("Native AUTO may temporarily prefer this tested method for new TLS connections.")
            appendLine("Evidence: plain failed 2/2, $hint verified YouTube HTML 2/2.")
            appendLine("The candidate expires on VPN/network reset or repeated weak live flows.")
            appendLine("This does NOT make YouTube app feeds, API, thumbnails or video verified.")
        } else {
            appendLine("No verified per-host AUTO preference inferred from this diagnostic.")
        }
        val apiHint = provisionalAPITransportHint(attempts)
        if (apiHint != null) {
            appendLine("Provisional exact-host AUTO transport candidate: $apiHint for youtubei.googleapis.com")
            appendLine("Evidence: plain failed 2/2; $apiHint received TLS-verified HTTP replies 2/2.")
            appendLine("HTTP replies to an unauthenticated GET do NOT prove real YouTube app feed/API access.")
            appendLine("The API-host preference is separate and temporary; no transfer to googlevideo.com.")
        } else {
            appendLine("No verified API-host transport preference inferred from this diagnostic.")
        }
        appendLine("Do not choose a global best DPI strategy from these 2-sample results.")
    }
}
