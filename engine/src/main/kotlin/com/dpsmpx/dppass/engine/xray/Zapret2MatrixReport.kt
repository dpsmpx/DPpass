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
        appendLine("=== DPpass — Google controls / YouTube API IPv4 / TLS / HTTP2 / QUIC ===")
        appendLine("Time: " + timestamp)
        appendLine("Network: " + network)
        appendLine("Target youtubei.googleapis.com; control www.google.com; same protected TCP/UDP probes.")
        appendLine("Fixed DoH: Cloudflare and Google HTTP/1.1; Quad9 HTTP/2 with verified ALPN; no UDP/53.")
        appendLine("Every A address is an indexed, sorted IPv4 position; no real IP is exported.")
        appendLine("HTTP/1.1 and HTTP/2: HTTPS with original SNI and Host; HTTP 2xx/4xx establishes transport only.")
        appendLine("QUIC: independent protected UDP/443 TLS 1.3 handshake with ALPN h3; HTTP/3 GET and video are NOT tested.")
        appendLine("TLS stages are per-probe socket events; not process-wide counters.")
        appendLine("Each request has a fixed deadline; HTTP bodies never appear in the report.")
        appendLine("No global DNS, routing or AUTO preference is changed.")
        appendLine()
        appendLine("Google control DoH preparation:")
        val controlDNS = rows.firstOrNull { it.target == "google_control_prepare" }?.result
        appendLine("control=www.google.com resolver=google outcome=" + (controlDNS?.outcome ?: "not_run") +
            " doh_http=" + (controlDNS?.httpStatus ?: 0) +
            " ipv4_count=" + (controlDNS?.dnsAnswers ?: 0) +
            " address_set_fingerprint=" + (controlDNS?.dnsFingerprint?.ifBlank { "-" } ?: "-"))
        appendLine("Verified YouTube API DoH preparation:")
        for (provider in providers) {
            val row = rows.firstOrNull { it.target == "youtube_api_matrix_" + provider + "_prepare" }
            val r = row?.result
            appendLine("resolver=" + provider + " outcome=" + (r?.outcome ?: "not_run") +
                " doh_http=" + (r?.httpStatus ?: 0) +
                " ipv4_count=" + (r?.dnsAnswers ?: 0) +
                " address_set_fingerprint=" + (r?.dnsFingerprint?.ifBlank { "-" } ?: "-"))
        }
        val prepared = rows.filter { it.target.startsWith("youtube_api_matrix_") &&
            it.target.endsWith("_prepare") && it.result.outcome == "dns_ready" }
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
        val control = tested.filter { it.target.startsWith("google_control_") }
        val youtube = tested.filter { it.target.startsWith("youtube_api_matrix_") }
        appendLine("Google control totals: ipv4_trials=" + control.size +
            " http_reachable=" + control.count { it.result.httpReachable } +
            " quic_verified=" + control.count { it.result.outcome == "quic_verified" })
        appendLine("YouTube API totals: prepared=" + prepared.size +
            " ipv4_trials=" + youtube.size +
            " http_reachable=" + youtube.count { it.result.httpReachable } +
            " quic_verified=" + youtube.count { it.result.outcome == "quic_verified" })
        val controlHTTP = control.any { it.result.httpReachable }
        val apiHTTP = youtube.any { it.result.httpReachable }
        val controlQUIC = control.any { it.result.outcome == "quic_verified" }
        val apiQUIC = youtube.any { it.result.outcome == "quic_verified" }
        if (controlHTTP && !apiHTTP && youtube.isNotEmpty()) {
            appendLine("CONTROL: Google HTTPS works on the same protected TCP probe; the tested YouTube addresses did not.")
            appendLine("Destination/SNI-selective behavior is plausible, but routes and remote IPs differ.")
        } else if (!controlHTTP && !apiHTTP && youtube.isNotEmpty()) {
            appendLine("CONTROL: Google and YouTube TCP probes both failed; YouTube-specific filtering is NOT established.")
            appendLine("Investigate protected Xray sockets, TCP routing, the mobile network and probe implementation.")
        }
        if (controlQUIC && !apiQUIC && youtube.any { it.result.protocol == "quic" }) {
            appendLine("CONTROL: Google QUIC handshake works on this protected UDP adapter; YouTube QUIC did not.")
        } else if (!controlQUIC && youtube.any { it.result.protocol == "quic" }) {
            appendLine("CONTROL: Google QUIC was not verified; site-specific QUIC filtering is NOT established.")
        }
        appendLine("HTTP reachability is not YouTube feed/API or video playback; QUIC handshake is not HTTP/3 transport.")
        appendLine("TLS EOF/reset/closed and timeout are reported separately; clienthello_sent has no observed reply.")
        appendLine("server_reply_seen is some peer bytes, not necessarily ServerHello; serverhello_seen is not verified TLS.")
        appendLine("A TLS-verified reply to one address does not establish access to other addresses or to googlevideo.com.")
        appendLine("Only tested IP indices, strategies and protocols are covered; repeat on the actual mobile network.")
    }
}
