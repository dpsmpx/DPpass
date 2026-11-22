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
    val success: Boolean get() = outcome == "ok" || outcome == "redirect"

    companion object {
        val outcomes: Set<String> = setOf(
            "ok", "redirect", "engine_off", "invalid_strategy", "invalid_timeout",
            "dial_failed", "timeout", "tls_failed", "tls_ca_failed",
            "request_failed", "http_failed", "http_status", "body_failed",
            "empty_body", "unsupported", "contract_error",
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
)

/** Complete plaintext report for clipboard; all attempts, including failures. */
object Zapret2GoogleReport {
    fun render(
        timestamp: String,
        network: String,
        quicForceTcp: Boolean,
        attempts: List<Zapret2GoogleAttempt>,
    ): String = buildString {
        appendLine("=== DPpass — Zapret2 Google HTTPS autotest ===")
        appendLine("Time: $timestamp")
        appendLine("Network: $network")
        appendLine("Target: https://google.com/ (GET; verified TLS certificate)")
        appendLine("Mode: experimental VpnService; QUIC->TCP=$quicForceTcp")
        appendLine("Scope: TCP/HTTPS; QUIC is not tested")
        appendLine("Redirects: reported, not followed")
        appendLine("Strategies: ${Zapret2ProbeCatalog.strategies.joinToString(", ")}")
        appendLine("Attempts: ${attempts.size}")
        appendLine()
        appendLine("Summary:")
        for (name in Zapret2ProbeCatalog.strategies) {
            val rows = attempts.filter { it.strategy == name }
            val ok = rows.count { it.result.success }
            val median = rows.filter { it.result.success }.map { it.result.elapsedMillis }
                .sorted().let { t -> if (t.isEmpty()) "-" else t[t.size / 2].toString() }
            val outcomes = rows.map { it.result.outcome }.joinToString(",").ifEmpty { "not_run" }
            appendLine("$name: $ok/${rows.size} HTTP replies; median_ms=$median; outcomes=$outcomes")
        }
        appendLine()
        appendLine("Every attempt:")
        attempts.forEachIndexed { index, a ->
            val r = a.result
            appendLine("${index + 1}. ${a.strategy} #${a.attempt}: " +
                "outcome=${r.outcome} http=${r.httpStatus} body_bytes=${r.bodyBytes} " +
                "elapsed_ms=${r.elapsedMillis} applied_delta=${r.appliedDelta} skipped_delta=${r.skippedDelta}")
        }
        appendLine()
        appendLine("Applied/skipped deltas are process-wide and may include unrelated apps.")
        appendLine("A Google HTTP response does not prove YouTube feed/video works.")
        appendLine("DNS/TCP/TLS, IP reachability and routing can fail independently.")
    }
}
