package com.dpsmpx.dppass.engine.xray

/**
 * Experimental, opt-in HTTP/3 address verification. Operates only on
 * anonymized probe outcomes in this single diagnostic run. Neither the
 * selected IPv4 nor test results are persisted or used by live VPN/AUTO.
 */
object Zapret2H3Policy {
    const val REQUIRED_QUIC_SUCCESSES = 3
    const val TTL_MILLIS = 5 * 60 * 1000L

    fun target(index: Int, protocol: String): String {
        require(index in 0..15)
        require(protocol in setOf("quic", "h3", "h3api"))
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
        appendLine("Fixed SNI/Host: youtubei.googleapis.com; fixed private Google DoH A-only IPv4.")
        appendLine("Strictly the original certificate-verified Xray UDP/443 outbound; no extra UDP socket or DNS.")
        appendLine("QUIC requires three successful independent TLS 1.3 / ALPN h3 handshakes.")
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
