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
            row.protocol.isEmpty() && row.ipIndex == 0 &&
            row.tlsStage.isEmpty() && row.alpn.isEmpty()
}

/** Fixed local cases only. Rows are admitted sequentially by the UI. */
internal enum class DptsLocalSuite(
    val reportLabel: String,
    val cases: List<DptsLocalCase>,
) {
    HTTP("DPpass local HTTP", listOf("plain", "http-hostcase", "http-hostows").map {
        DptsLocalCase("HTTP / $it", it, "local_http_hostcase", "local_http_verified")
    }),
    HTTP_COMBINED("DPpass combined local HTTP", listOf("plain", "http-host-combined").map {
        DptsLocalCase("HTTP / $it", it, "local_http_hostcase", "local_http_verified")
    }),
    TLS("DPpass local TLS", listOf("1.2" to "local_tls12", "1.3" to "local_tls13").flatMap { (version, target) ->
        listOf("plain", "multisplit", "tlsrec-split").map {
            DptsLocalCase("TLS $version / $it", it, target, "local_tls_verified")
        }
    }),
    TLS_CHAIN("DPpass local TLS chain", listOf("1.2" to "local_tls12", "1.3" to "local_tls13").flatMap { (version, target) ->
        listOf("plain", "tlsrec-chain").map {
            DptsLocalCase("TLS $version / $it", it, target, "local_tls_verified")
        }
    }),
    ACCEPTANCE("DPpass local HTTP/TLS", HTTP.cases + TLS.cases);

    companion object {
        fun fromScript(source: String): DptsLocalSuite? {
            val plan = try {
                com.dpsmpx.dppass.engine.xray.DptsScript.compile(source)
            } catch (_: IllegalArgumentException) { return null }
            return fromId(plan.suite)
        }

        fun fromId(id: String?): DptsLocalSuite? = when (id) {
            "local_http_hostcase" -> HTTP
            "local_http_combined" -> HTTP_COMBINED
            "local_tls" -> TLS
            "local_tls_chain" -> TLS_CHAIN
            "local_acceptance" -> ACCEPTANCE
            else -> null
        }

        fun allowsOfflineProbe(method: String, target: String): Boolean =
            entries.any { suite -> suite.cases.any { it.method == method && it.target == target } }
    }

    val budgetMs: Long get() = cases.size * 5000L

    fun report(rows: List<Zapret2GoogleProbe>, interruption: DptsInterruption? = null,
        buildIdentity: DptsBuildIdentity? = null): String =
        buildString {
            appendLine("=== $reportLabel self-test ===")
            appendLine(buildIdentity?.report() ?: "BUILD: identity_unavailable")
            appendLine("Loopback only; no DNS, Internet or system trust changes.")
            if (cases.any { it.target == "local_http_hostcase" }) appendLine("Exact HTTP request bytes, Host value and body.")
            if (cases.any { it.target.startsWith("local_tls") }) appendLine("Fresh private trust anchor, fixed TLS versions and application bytes.")
            appendLine("budget_ms=$budgetMs")
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
            for (group in cases.map { it.label.substringBefore(" / ") }.distinct()) {
                val indices = cases.indices.filter { cases[it].label.substringBefore(" / ") == group }
                val count = indices.count { i -> rows.getOrNull(i)?.let { cases[i].verified(it) } == true }
                appendLine("$group: $count/${indices.size}")
            }
            appendLine("ACCEPTANCE: " + if (completed && verified == cases.size) "PASS" else "NOT_VERIFIED")
            appendLine("AUTO and training unchanged. No proof of remote access or packet segmentation.")
        }
}
