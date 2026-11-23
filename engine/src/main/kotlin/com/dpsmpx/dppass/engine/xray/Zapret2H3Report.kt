package com.dpsmpx.dppass.engine.xray

/**
 * Experimental, opt-in HTTP/3 address verification. Operates only on
 * anonymized probe outcomes in this single diagnostic run. Neither the
 * selected IPv4 nor test results are persisted or used by live VPN/AUTO.
 */
object Zapret2H3Policy {
    const val REQUIRED_QUIC_SUCCESSES = 3
    const val MAX_PEER_REPLY_RECHECKS = 2
    const val TTL_MILLIS = 5 * 60 * 1000L

    // Diagnostic-only second samples after an inconclusive UDP peer reply.
    // An initial failed handshake is NEVER promoted to a stable 3/3 candidate.
    fun peerReplyRechecks(attempts: List<Zapret2GoogleAttempt>): List<Int> =
        attempts.asSequence().filter {
            it.attempt == 1 &&
                it.result.protocol == "quic" &&
                it.result.outcome == "quic_timeout_after_reply" &&
                it.result.tlsStage.startsWith("quic_peer_") &&
                it.result.ipIndex in 0..15 &&
                it.target == target(it.result.ipIndex, "quic")
        }.map { it.result.ipIndex }.distinct().take(MAX_PEER_REPLY_RECHECKS).toList()

    fun target(index: Int, protocol: String): String {
        require(index in 0..15)
        require(protocol in setOf("quic", "quicv2", "h3", "h3api"))
        return "youtube_api_h3_ip" + index.toString().padStart(2, '0') + "_" + protocol
    }

    fun fresh(preparedAtMillis: Long, nowMillis: Long): Boolean =
        nowMillis >= preparedAtMillis && nowMillis - preparedAtMillis < TTL_MILLIS

    fun stable(attempts: List<Zapret2GoogleAttempt>): Boolean =
        attempts.size == REQUIRED_QUIC_SUCCESSES &&
            attempts.all {
                it.result.protocol == "quic" &&
                    it.result.outcome == "quic_verified" &&
                    it.result.tlsStage == "quic_tls_verified" &&
                    it.result.alpn == "h3"
            }
}

object Zapret2H3Report {
    fun render(
        timestamp: String,
        network: String,
        rows: List<Zapret2GoogleAttempt>,
    ): String = buildString {
        appendLine("=== DPpass — YouTube API protected QUIC retry / real HTTP3 ===")
        appendLine("Time: $timestamp")
        appendLine("Network: $network")
        appendLine("YouTube SNI/Host: youtubei.googleapis.com; verified private Google DoH A-only IPv4.")
        appendLine("Same-run www.google.com QUIC control before/after the scan (fixed verified Google DoH).")
        appendLine("All QUIC trials use original protected Xray UDP/443; no unprotected socket or system DNS.")
        appendLine("QUIC requires three successful independent TLS 1.3 / ALPN h3 handshakes.")
        appendLine("First peer UDP reply is classified by public QUIC header shape only; it is NOT TLS verification.")
        appendLine("Up to two peer-reply timeouts are rechecked once for evidence; failed first attempts never qualify for H3.")
        appendLine("If QUIC v1 has no stable address, QUIC v2 (RFC 9369) is tested separately for diagnostics only.")
        appendLine("QUIC v2 handshakes do not bypass the three-success v1 gate for HTTP/3 in this build.")
        appendLine("A validated IP index expires in five minutes and is discarded with this diagnostic run.")
        appendLine("An actual HTTP/3 GET / and a fixed anonymous JSON HTTP/3 POST /youtubei/v1/browse follow.")
        appendLine("The POST uses fixed public client context only; no personal identity, cookies, keys or credentials.")
        appendLine("No raw IPs, URLs containing user data, certificates or response bodies are reported.")
        appendLine("Normal VPN routing, global DNS, AUTO and neural weights are never changed.")
        appendLine()
        val prep = rows.firstOrNull { it.target == "youtube_api_h3_prepare" }?.result
        appendLine("DNS: outcome=" + (prep?.outcome ?: "not_run") +
            " doh_http=" + (prep?.httpStatus ?: 0) +
            " ipv4_count=" + (prep?.dnsAnswers ?: 0) +
            " address_set_fingerprint=" + (prep?.dnsFingerprint?.ifBlank { "-" } ?: "-"))
        val googlePreparation = rows.firstOrNull { it.target == "google_control_prepare" }?.result
        val googleChecks = rows.filter { it.target == "google_control_ip00_quic" }
        val before = googleChecks.firstOrNull { it.attempt == 1 }?.result
        val after = googleChecks.firstOrNull { it.attempt == 2 }?.result
        fun controlStatus(result: Zapret2GoogleProbe?): String =
            if (result == null) "not_run" else
                result.outcome + " stage=" + result.tlsStage + " alpn=" + result.alpn
        appendLine("Google QUIC control: doh=" +
            (googlePreparation?.outcome ?: "not_run") +
            " before=" + controlStatus(before) +
            " after=" + controlStatus(after))
        if (before?.outcome == "quic_verified" && after?.outcome == "quic_verified" &&
            before.tlsStage == "quic_tls_verified" && after.tlsStage == "quic_tls_verified" &&
            before.alpn == "h3" && after.alpn == "h3") {
            appendLine("CONTROL: Google protected QUIC worked before and after the YouTube scan; this does not establish the reason for YouTube failures.")
        } else {
            appendLine("CONTROL: Google protected QUIC was not verified at both endpoints of this scan; YouTube-specific filtering is NOT established.")
        }
        val googleV2 = rows.filter { it.target == "google_control_ip00_quicv2" }
        val v2Before = googleV2.firstOrNull { it.attempt == 1 }?.result
        val v2After = googleV2.firstOrNull { it.attempt == 2 }?.result
        appendLine("Google QUIC v2 control: before=" + controlStatus(v2Before) +
            " after=" + controlStatus(v2After))
        if (v2Before != null || v2After != null) {
            if (v2Before?.outcome == "quic_verified" && v2After?.outcome == "quic_verified" &&
                v2Before.alpn == "h3" && v2After.alpn == "h3") {
                appendLine("CONTROL: Google QUIC v2 verified twice; compare YouTube v2 outcomes without inferring the cause.")
            } else {
                appendLine("CONTROL: QUIC v2 baseline not verified at both ends; negative YouTube v2 outcomes are inconclusive.")
            }
        }
        appendLine("Indexed IPv4 trials:")
        val trials = rows.filter { it.target.startsWith("youtube_api_h3_ip") }
        val perIndex = trials.groupBy { it.result.ipIndex }
        for ((index, group) in perIndex.toSortedMap()) {
            val quic = group.filter { it.result.protocol == "quic" }
            appendLine("  ipv4_index=$index quic_successes=" +
                quic.count { it.result.outcome == "quic_verified" } +
                "/" + quic.size +
                " stable=" + Zapret2H3Policy.stable(quic))
            for (row in group) {
                val r = row.result
                appendLine("    " + r.protocol + " attempt=" + row.attempt +
                    " outcome=" + r.outcome + " stage=" + r.tlsStage +
                    " alpn=" + r.alpn + " http=" + r.httpStatus +
                    " body_bytes_bounded=" + r.bodyBytes +
                    " elapsed_ms=" + r.elapsedMillis)
            }
        }
        val stable = perIndex.filter { (_, group) ->
            Zapret2H3Policy.stable(group.filter { it.result.protocol == "quic" })
        }.keys.sorted()
        val v2Trials = trials.filter { it.result.protocol == "quicv2" }
        appendLine("Experimental QUIC v2: tested_ipv4=" +
            v2Trials.map { it.result.ipIndex }.distinct().size +
            " tls_verified=" + v2Trials.count {
                it.result.outcome == "quic_verified" &&
                    it.result.tlsStage == "quic_tls_verified" && it.result.alpn == "h3"
            } + "; HTTP/3 v2 NOT attempted.")
        val h3Reply = trials.firstOrNull {
            it.result.protocol == "h3" && it.result.httpReachable
        }
        val appJSON = trials.firstOrNull {
            it.result.protocol == "h3api" && it.result.outcome == "h3_api_json_valid"
        }
        appendLine("Totals: tested_ipv4=" + perIndex.size +
            " stable_quic_indices=" + stable.size +
            " h3_get_http_reachable=" + trials.count {
                it.result.protocol == "h3" && it.result.httpReachable
            } +
            " api_valid_json=" + trials.count {
                it.result.protocol == "h3api" && it.result.outcome == "h3_api_json_valid"
            })
        appendLine("Selected experimental HTTP/3 transport: ipv4_index=" +
            (h3Reply?.result?.ipIndex?.toString() ?: "-"))
        appendLine("Anonymous API JSON response: ipv4_index=" +
            (appJSON?.result?.ipIndex?.toString() ?: "-"))
        if (prep?.outcome != "dns_ready") {
            appendLine("No IP was tested: verified DoH preparation failed.")
        } else if (stable.isEmpty()) {
            appendLine("No address passed 3/3 independent QUIC handshakes. No HTTP/3 request attempted.")
        } else if (h3Reply == null) {
            appendLine("QUIC handshake alone worked; no tested address returned HTTP/3 response headers.")
        } else if (appJSON == null) {
            appendLine("HTTP/3 transport worked; a usable YouTube feed is NOT established.")
        } else {
            appendLine("Anonymous HTTP/3 API returned syntactically valid JSON; feed or video playback remains UNTESTED.")
        }
        appendLine("HTTP 2xx/4xx on GET proves transport only; API HTTP 4xx means the anonymous POST was rejected.")
        appendLine("h3_api_json_valid verifies bounded JSON syntax only, not its feed contents or authorized playback.")
        appendLine("h3_api_body_limit means JSON was larger than the 8 KiB safety read limit; it is NOT a failure proof.")
        appendLine("Only indexed IPs and current underlying network were tested.")
    }
}
