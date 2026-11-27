package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsInterruption
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe

internal data class DptsLocalCase(
    val label: String,
    val method: String,
    val target: String,
    val outcome: String,
) {
    fun verified(row: Zapret2GoogleProbe): Boolean =
        row.outcome == outcome && row.httpStatus == 0 && row.bodyBytes == 0L &&
            row.appliedDelta == (if (method == "plain") 0L else 1L) &&
            row.skippedDelta == 0L && row.elapsedMillis >= 0L &&
            row.dnsFingerprint.isEmpty() && row.dnsAnswers == 0 &&
            row.protocol.isEmpty()
}

/** Fixed local cases only. Rows are admitted sequentially by the UI. */
internal enum class DptsLocalSuite(
    val reportLabel: String,
    val cases: List<DptsLocalCase>,
) {
    HTTP("DPpass local HTTP", listOf("plain", "http-hostcase", "http-hostows").map {
        DptsLocalCase("HTTP / $it", it, "local_http_hostcase", "local_http_verified")
    }),
    TLS("DPpass local TLS", listOf("1.2" to "local_tls12", "1.3" to "local_tls13").flatMap { (version, target) ->
        listOf("plain", "multisplit", "tlsrec-split").map {
            DptsLocalCase("TLS $version / $it", it, target, "local_tls_verified")
        }
    });

    fun report(rows: List<Zapret2GoogleProbe>, interruption: DptsInterruption? = null): String =
        buildString {
            appendLine("=== $reportLabel self-test ===")
            appendLine("Loopback only; no DNS, Internet or system trust changes.")
            appendLine(if (this@DptsLocalSuite == HTTP)
                "Exact HTTP request bytes, Host value and body."
                else "Fresh private trust anchor, fixed TLS versions and application bytes.")
            val completed = interruption == null && rows.size == cases.size
            appendLine(if (completed) "RUN: completed; training_eligible=false"
                else "RUN: interrupted; reason=${interruption?.wire ?: "incomplete_rows"}; training_eligible=false")
            appendLine("Executed: ${minOf(rows.size, cases.size)}/${cases.size};" +
                " missing=${(cases.size - rows.size).coerceAtLeast(0)};" +
                " extra=${(rows.size - cases.size).coerceAtLeast(0)}")
            var verified = 0
            for ((case, row) in cases.zip(rows)) {
                val ok = case.verified(row)
                if (ok) verified++
                appendLine("${case.label}: ${if (ok) "verified" else row.outcome + " / unconfirmed"};" +
                    " applied=${row.appliedDelta}; skipped=${row.skippedDelta}; elapsed_ms=${row.elapsedMillis}")
            }
            appendLine("Verified: $verified/${cases.size}")
            appendLine("AUTO and training unchanged. No proof of remote access or packet segmentation.")
        }
}
