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
        val matching = rows.indices.all { i -> plan.probes[i].matches(rows[i]) }
        if (!matching) return Evidence(reason = "mismatched_probe_rows")

        val transportCount = rows.indices.count { i ->
            plan.probes[i].handshakeVerified(rows[i].result)
        }
        val htmlCount = if (plan.host == "www.youtube.com")
            rows.indices.count { i -> plan.probes[i].boundedHttpsSuccess(rows[i].result) }
        else 0
        val base = Evidence(transportVerified = transportCount, htmlVerified = htmlCount, reason = "no_verified_html")
        if (!plan.observeLearning) return base.copy(reason = "learning_disabled_in_script")
        if (plan.host != "www.youtube.com")
            return base.copy(reason = if (transportCount > 0) "transport_only_not_content" else "no_verified_transport")
        val fingerprints = rows.map { it.result.dnsFingerprint }.distinct()
        val counts = rows.map { it.result.dnsAnswers }.distinct()
        if (fingerprints.size != 1 || !fingerprints.single().matches(Regex("[0-9a-f]{8}")) ||
            counts.size != 1 || counts.single() !in 1..8 ||
            plan.probes.any { it.ipIndex !in 0 until counts.single() })
            return base.copy(reason = "dns_address_set_changed")

        fun on(ip: Int, protocol: String, method: String): List<Pair<DptsProbe, Zapret2GoogleProbe>>? {
            return (1..Zapret2SiteSearch.ATTEMPTS).map { attempt ->
                val indices = plan.probes.indices.filter { i ->
                    val p = plan.probes[i]
                    p.ipIndex == ip && p.attempt == attempt && p.phase == "https" &&
                        p.protocol == protocol && p.method == method
                }
                if (indices.size != 1) return null
                val index = indices.single()
                plan.probes[index] to rows[index].result
            }
        }
        val proofs = mutableListOf<AddressProof>()
        for (ip in plan.probes.map { it.ipIndex }.distinct()) {
            for (protocol in listOf("h1", "h2")) {
                val baseline = on(ip, protocol, "plain") ?: continue
                // Only coherent ClientHello timeouts without any reply are
                // a failed plain baseline; contradictory evidence cannot train.
                if (baseline.any { (_, r) ->
                    r.outcome != "timeout_tls_no_reply" || r.tlsStage != "clienthello_sent" ||
                        r.alpn != "-" || r.httpStatus != 0 || r.bodyBytes != 0
                }) continue
                for (method in trainable) {
                    if (on(ip, protocol, method)?.all { (spec, r) -> spec.boundedHttpsSuccess(r) } == true)
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

}
