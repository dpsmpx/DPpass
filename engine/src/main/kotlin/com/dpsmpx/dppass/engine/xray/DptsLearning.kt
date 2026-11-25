package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog

/**
 * Report transport separately from application content. Only a repeated
 * matched YouTube HTML experiment can teach the existing global TLS head.
 * A single working IP remains address-scoped evidence, not a host-wide label.
 */
object DptsLearning {
    val trainable = Zapret2ProbeCatalog.verifiedHtmlMethods

    data class AddressProof(val ipIndex: Int, val protocol: String, val method: String)
    data class Evidence(
        val transportVerified: Int = 0,
        val htmlVerified: Int = 0,
        val addressProofs: List<AddressProof> = emptyList(),
        val winners: List<String> = emptyList(),
        val reason: String,
    ) {
        fun report(): String =
            "transport_verified=$transportVerified html_verified=$htmlVerified address_proofs=" +
                addressProofs.joinToString(",") { "${it.ipIndex}:${it.protocol}:${it.method}" }.ifEmpty { "-" }
    }

    fun confirmedWinners(plan: DptsPlan, rows: List<Zapret2GoogleAttempt>): List<String> =
        analyze(plan, rows).winners

    fun analyze(plan: DptsPlan, rows: List<Zapret2GoogleAttempt>): Evidence {
        if (plan.suite != null || rows.size != plan.probes.size ||
            rows.isEmpty() || plan.probes.size > DptsScript.MAX_PROBES)
            return Evidence(reason = "incomplete_or_legacy_suite")
        val matching = rows.indices.all { i ->
            val spec = plan.probes[i]
            val row = rows[i]
            row.strategy == spec.method && row.attempt == spec.attempt &&
                row.target == spec.target && row.result.ipIndex == spec.ipIndex &&
                row.result.protocol == spec.protocol
        }
        if (!matching) return Evidence(reason = "mismatched_probe_rows")

        fun transport(r: Zapret2GoogleProbe): Boolean =
            (r.tlsStage == "tls_verified" && r.alpn in setOf("http/1.1", "h2")) ||
                (r.outcome == "quic_verified" && r.tlsStage == "quic_tls_verified" && r.alpn == "h3")
        fun html(r: Zapret2GoogleProbe, protocol: String): Boolean =
            r.outcome == "ok" && r.tlsStage == "tls_verified" &&
                r.alpn == ifAlpn(protocol) && r.httpStatus in 200..299 && r.bodyBytes >= 128

        val transportCount = rows.count { transport(it.result) }
        val htmlCount = if (plan.host == "www.youtube.com")
            rows.indices.count { i ->
                plan.probes[i].phase == "https" && plan.probes[i].protocol in setOf("h1", "h2") &&
                    html(rows[i].result, plan.probes[i].protocol)
            } else 0
        val base = Evidence(transportVerified = transportCount, htmlVerified = htmlCount, reason = "no_verified_html")
        if (!plan.observeLearning) return base.copy(reason = "learning_disabled_in_script")
        if (plan.host != "www.youtube.com")
            return base.copy(reason = if (transportCount > 0) "transport_only_not_content" else "no_verified_transport")
        val fingerprints = rows.map { it.result.dnsFingerprint }.distinct()
        if (fingerprints.size != 1 || fingerprints.single() in setOf("", "-"))
            return base.copy(reason = "dns_address_set_changed")

        fun on(ip: Int, protocol: String, method: String): List<Zapret2GoogleProbe>? {
            return (1..Zapret2SiteSearch.ATTEMPTS).map { attempt ->
                val indices = plan.probes.indices.filter { i ->
                    val p = plan.probes[i]
                    p.ipIndex == ip && p.attempt == attempt && p.phase == "https" &&
                        p.protocol == protocol && p.method == method
                }
                if (indices.size != 1) return null
                rows[indices.single()].result
            }
        }
        val proofs = mutableListOf<AddressProof>()
        for (ip in plan.probes.map { it.ipIndex }.distinct()) {
            for (protocol in listOf("h1", "h2")) {
                val baseline = on(ip, protocol, "plain") ?: continue
                // A valid plain TLS response is reachability, not failure.
                if (baseline.any(::transport)) continue
                if (baseline.any { it.outcome != "timeout_tls_no_reply" }) continue
                for (method in trainable) {
                    if (on(ip, protocol, method)?.all { html(it, protocol) } == true)
                        proofs += AddressProof(ip, protocol, method)
                }
            }
        }
        val winners = trainable.filter { method ->
            listOf("h1", "h2").any { protocol ->
                proofs.filter { it.method == method && it.protocol == protocol }
                    .map { it.ipIndex }.distinct().size >= 2
            }
        }
        return base.copy(addressProofs = proofs, winners = winners,
            reason = when {
                winners.isNotEmpty() -> "verified_two_ips"
                proofs.isNotEmpty() -> "verified_single_ip_only"
                htmlCount > 0 -> "no_matched_failed_plain_and_three_repeats"
                transportCount > 0 -> "transport_only_not_content"
                else -> "no_verified_transport"
            })
    }

    private fun ifAlpn(protocol: String): String = if (protocol == "h2") "h2" else "http/1.1"
}
