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

    companion object {
        val outcomes: Set<String> = setOf(
            "ok", "redirect", "engine_off", "invalid_strategy", "invalid_timeout",
            "dial_failed", "timeout", "tls_failed", "tls_ca_failed",
            "request_failed", "http_failed", "http_status", "body_failed",
            "empty_body", "content_type_mismatch", "content_invalid",
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
        appendLine("Targets: google_final=www.google.com/ (HTML after google.com 301); " +
            "youtube_home=www.youtube.com/ (HTML); " +
            "youtube_thumbnail=i.ytimg.com/vi/jNQXAC9IVRw/hqdefault.jpg (JPEG)")
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
                val ok = rows.count { it.result.success }
                val median = medianMillis(rows.filter { it.result.success }
                    .map { it.result.elapsedMillis })
                val outcomes = rows.map { it.result.outcome }.joinToString(",").ifEmpty { "not_run" }
                appendLine("  $strategy: $ok/${rows.size} content; median_ok_ms=$median; outcomes=$outcomes")
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
        appendLine("No winning DPI strategy is auto-selected from this test.")
    }
}
