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
        val tlsVerified: Int = 0,
        val addressProofs: List<AddressProof> = emptyList(),
        val winners: List<String> = emptyList(),
        val reason: String,
        val timeoutMismatchPairs: Int = 0,
        val actionUnverifiedPairs: Int = 0,
        val elapsedInvalidPairs: Int = 0,
    ) {
        fun report(): String =
            "transport_verified=$transportVerified html_verified=$htmlVerified tls_verified=$tlsVerified address_proofs=" +
                addressProofs.joinToString(",") { "${it.ipIndex}:${it.protocol}:${it.method}" }.ifEmpty { "-" } +
                "; timeout_mismatch_pairs=$timeoutMismatchPairs; action_unverified_pairs=$actionUnverifiedPairs;" +
                " elapsed_invalid_pairs=$elapsedInvalidPairs"
    }

    fun confirmedWinners(plan: DptsPlan, rows: List<Zapret2GoogleAttempt>): List<String> =
        analyze(plan, rows).winners

    fun analyze(plan: DptsPlan, rows: List<Zapret2GoogleAttempt>): Evidence {
        if (plan.suite != null || rows.size != plan.probes.size ||
            rows.isEmpty() || plan.probes.size > DptsScript.MAX_PROBES)
            return Evidence(reason = "incomplete_or_legacy_suite")
        val matching = rows.indices.all { i -> plan.probes[i].matches(rows[i]) }
        if (!matching) return Evidence(reason = "mismatched_probe_rows")
        if (!DptsScript.uniqueProbeIdentities(plan))
            return Evidence(reason = "duplicate_probe_identity")
        if (!DptsScript.probePlanValid(plan))
            return Evidence(reason = "invalid_probe_plan")

        val fingerprints = rows.map { it.result.dnsFingerprint }.distinct()
        val counts = rows.map { it.result.dnsAnswers }.distinct()
        if (fingerprints.size != 1 || counts.size != 1 ||
            !DptsScript.dnsSetValid(plan, fingerprints.single(), counts.single()))
            return Evidence(reason = "dns_address_set_changed")

        val tlsCount = rows.indices.count { i ->
            plan.probes[i].handshakeVerified(rows[i].result)
        }
        val transportCount = rows.indices.count { i ->
            plan.probes[i].transportVerified(rows[i].result)
        }
        val htmlCount = if (plan.host == "www.youtube.com")
            rows.indices.count { i -> plan.probes[i].boundedHttpsSuccess(rows[i].result) }
        else 0
        val base = Evidence(transportVerified = transportCount, htmlVerified = htmlCount,
            tlsVerified = tlsCount, reason = "no_verified_html")
        if (!plan.observeLearning) return base.copy(reason = "learning_disabled_in_script")
        if (plan.host != "www.youtube.com")
            return base.copy(reason = if (tlsCount > 0) "transport_only_not_content" else "no_verified_transport")

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
        var timeoutMismatchPairs = 0
        var actionUnverifiedPairs = 0
        var elapsedInvalidPairs = 0
        for (ip in plan.probes.map { it.ipIndex }.distinct()) {
            for (protocol in listOf("h1", "h2")) {
                val baseline = on(ip, protocol, "plain") ?: continue
                // Only coherent ClientHello timeouts without any reply are
                // a failed plain baseline; contradictory evidence cannot train.
                if (baseline.any { (_, r) ->
                    r.outcome != "timeout_tls_no_reply" || r.tlsStage != "clienthello_sent" ||
                        r.alpn != "-" || r.httpStatus != 0 || r.bodyBytes != 0L
                }) continue
                for (method in trainable) {
                    val candidate = on(ip, protocol, method) ?: continue
                    if (!candidate.all { (spec, r) -> spec.boundedHttpsSuccess(r) }) continue
                    // A longer deadline can make an unchanged connection appear better.
                    // Every repeat must have the same budget as its matching control.
                    if (baseline.map { it.first.timeoutMs } != candidate.map { it.first.timeoutMs }) {
                        timeoutMismatchPairs++
                        continue
                    }
                    // Request-owned counts prove that the intended operation ran.
                    // Lost context or skipped/ambiguous actions cannot train the model.
                    if (baseline.any { (_, r) -> r.appliedDelta != 0L || r.skippedDelta != 0L } ||
                        candidate.any { (_, r) -> r.appliedDelta != 1L || r.skippedDelta != 0L }) {
                        actionUnverifiedPairs++
                        continue
                    }
                    if (baseline.any { (_, r) -> r.elapsedMillis < 0L } ||
                        candidate.any { (spec, r) -> r.elapsedMillis !in 0L..spec.timeoutMs.toLong() }) {
                        elapsedInvalidPairs++
                        continue
                    }
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
            timeoutMismatchPairs = timeoutMismatchPairs, actionUnverifiedPairs = actionUnverifiedPairs,
            elapsedInvalidPairs = elapsedInvalidPairs, reason = when {
                winners.isNotEmpty() -> "verified_two_ips"
                proofs.isNotEmpty() -> "verified_single_ip_only"
                timeoutMismatchPairs > 0 -> "incomparable_timeout_budgets"
                actionUnverifiedPairs > 0 -> "method_application_unverified"
                elapsedInvalidPairs > 0 -> "invalid_elapsed_evidence"
                htmlCount > 0 -> "no_matched_failed_plain_and_three_repeats"
                tlsCount > 0 -> "transport_only_not_content"
                else -> "no_verified_transport"
            })
    }

}
