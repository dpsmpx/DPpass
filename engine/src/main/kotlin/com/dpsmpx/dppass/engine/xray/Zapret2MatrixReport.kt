package com.dpsmpx.dppass.engine.xray

/**
 * A report for the explicitly requested fixed-target IPv4 matrix.
 * Address positions are not IP literals. No request/response body, location,
 * routing change or automatic strategy preference is recorded.
 */
object Zapret2MatrixReport {
    val providers = listOf("cloudflare", "google", "quad9")

    fun render(
        timestamp: String,
        network: String,
        rows: List<Zapret2GoogleAttempt>,
    ): String = buildString {
        appendLine("=== DPpass — YouTube API IPv4 / TLS / HTTP2 / QUIC matrix ===")
        appendLine("Time: " + timestamp)
        appendLine("Network: " + network)
        appendLine("Fixed host: youtubei.googleapis.com; private certificate-verified DoH over TCP/443; no UDP/53.")
        appendLine("Every A address is an indexed, sorted IPv4 position; no real IP is exported.")
        appendLine("HTTP/1.1 and HTTP/2: HTTPS with original SNI and Host; HTTP 2xx/4xx establishes transport only.")
        appendLine("QUIC: independent protected UDP/443 TLS 1.3 handshake with ALPN h3; HTTP/3 GET and video are NOT tested.")
        appendLine("TLS stages are per-probe socket events; not process-wide counters.")
        appendLine("Each request has a fixed deadline; HTTP bodies never appear in the report.")
        appendLine("No global DNS, routing or AUTO preference is changed.")
        appendLine()
        appendLine("Verified DoH preparation:")
        for (provider in providers) {
            val row = rows.firstOrNull { it.target == "youtube_api_matrix_" + provider + "_prepare" }
            val r = row?.result
            appendLine("resolver=" + provider + " outcome=" + (r?.outcome ?: "not_run") +
                " doh_http=" + (r?.httpStatus ?: 0) +
                " ipv4_count=" + (r?.dnsAnswers ?: 0) +
                " address_set_fingerprint=" + (r?.dnsFingerprint?.ifBlank { "-" } ?: "-"))
        }
        val prepared = rows.filter { it.target.endsWith("_prepare") && it.result.outcome == "dns_ready" }
        val equalFingerprints = prepared.groupBy { it.result.dnsFingerprint + "/" + it.result.dnsAnswers }
        for (group in equalFingerprints.values) {
            if (group.size > 1) appendLine("Duplicate short RRset fingerprint: " +
                group.joinToString(",") { it.target.removePrefix("youtube_api_matrix_").removeSuffix("_prepare") } +
                " (only the first provider was probed per IP to avoid duplicates).")
        }
        appendLine("A short fingerprint match is not cryptographic proof of identical addresses; CDN geo steering is possible.")
        appendLine()
        appendLine("Per indexed IPv4:")
        val tested = rows.filter { it.result.protocol in setOf("h1", "h2", "quic") }
        val groups = tested.groupBy { it.target.substringBefore("_ip") }
        for ((source, group) in groups) {
            appendLine("SOURCE " + source)
            for (index in group.map { it.result.ipIndex }.distinct().sorted()) {
                appendLine("  ipv4_index=" + index)
                for (row in group.filter { it.result.ipIndex == index }) {
                    val r = row.result
                    appendLine("    " + r.protocol + "/" + row.strategy +
                        ": outcome=" + r.outcome +
                        " stage=" + r.tlsStage +
                        " alpn=" + r.alpn +
                        " http=" + r.httpStatus +
                        " elapsed_ms=" + r.elapsedMillis)
                }
            }
        }
        if (tested.isEmpty()) appendLine("No IPv4 trials completed; inspect resolver preparation outcomes.")
        appendLine()
        appendLine("Totals: prepared=" + prepared.size + " ipv4_trials=" + tested.size +
            " http_reachable=" + tested.count { it.result.httpReachable } +
            " quic_verified=" + tested.count { it.result.outcome == "quic_verified" })
        appendLine("HTTP reachability is not YouTube feed/API or video playback; QUIC handshake is not HTTP/3 transport.")
        appendLine("For TLS failures, clienthello_sent means sent without an observed reply; server_reply_seen means some peer bytes, NOT proof of ServerHello.")
        appendLine("A TLS-verified reply to one address does not establish access to other addresses or to googlevideo.com.")
        appendLine("Only tested IP indices, strategies and protocols are covered; repeat on the actual mobile network.")
    }
}
