package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsInterruption
import com.dpsmpx.dppass.engine.xray.DptsPlan
import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleAttempt
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe
import com.dpsmpx.dppass.engine.xray.Zapret2SiteSearch

/** Read-only, bounded export. Missing and unbound observations never look like measured failures. */
internal object DptsCsv {
    private val safeToken = Regex("[A-Za-z0-9][A-Za-z0-9._/-]{0,127}")
    private val columns = listOf("format", "run_state", "interruption", "network", "host",
        "dns_fingerprint", "dns_answers", "step", "phase", "protocol", "method", "ip_index",
        "attempt", "timeout_ms", "binding", "outcome", "tls_stage", "alpn", "http_status",
        "body_bytes_bounded", "elapsed_ms", "applied_delta", "skipped_delta", "handshake_verified",
        "transport_verified", "bounded_http_success", "content_verified")

    private fun token(value: String): String = value.takeIf { safeToken.matches(it) }.orEmpty()

    fun render(plan: DptsPlan, network: String, prepared: Zapret2GoogleProbe,
        rows: List<Zapret2GoogleAttempt>, interruption: DptsInterruption? = null): String = buildString {
        require(plan.suite == null && plan.probes.size in 1..DptsScript.MAX_PROBES)
        val validDns = DptsScript.preparationValid(plan, prepared)
        val complete = interruption == null && DptsScript.completeEvidence(plan, prepared, rows)
        val state = when {
            interruption != null -> "interrupted"
            complete -> "complete"
            else -> "incomplete"
        }
        append(columns.joinToString(",")).append("\r\n")
        for ((index, spec) in plan.probes.withIndex()) {
            val row = rows.getOrNull(index)
            val matched = row != null && validDns && DptsScript.rowMatchesPreparation(spec, row, prepared)
            val result = if (matched) row?.result else null
            val binding = if (row == null) "missing" else if (matched) "matched" else "unbound"
            val bounded = result?.let { spec.boundedHttpsSuccess(it) && plan.host != Zapret2SiteSearch.YOUTUBE_API_HOST }
            val fields = listOf("dpts1", state, interruption?.wire.orEmpty(), token(network), token(plan.host),
                if (validDns) token(prepared.dnsFingerprint) else "",
                if (validDns) prepared.dnsAnswers.toString() else "", index.toString(), token(spec.phase),
                token(spec.protocol), token(spec.method), spec.ipIndex.toString(), spec.attempt.toString(),
                spec.timeoutMs.toString(), binding, result?.outcome?.let(::token).orEmpty(),
                result?.tlsStage?.let(::token).orEmpty(), result?.alpn?.let(::token).orEmpty(),
                result?.httpStatus?.toString().orEmpty(), result?.bodyBytes?.toString().orEmpty(),
                result?.elapsedMillis?.toString().orEmpty(), result?.appliedDelta?.toString().orEmpty(),
                result?.skippedDelta?.toString().orEmpty(), result?.let { spec.handshakeVerified(it) }?.toString().orEmpty(),
                result?.let { spec.transportVerified(it) }?.toString().orEmpty(), bounded?.toString().orEmpty(),
                bounded?.let { it && plan.host in setOf("www.youtube.com", "i.ytimg.com") }?.toString().orEmpty())
            append(fields.joinToString(",")).append("\r\n")
        }
    }
}
