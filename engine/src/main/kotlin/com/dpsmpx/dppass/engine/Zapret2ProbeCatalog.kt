package com.dpsmpx.dppass.engine

/**
 * Complete user-visible VpnService TCP strategy catalog, plus a plain
 * baseline. Only internal Google HTTPS probes may force these outbounds;
 * no traffic-routing rule refers to their tags.
 *
 * QUIC is deliberately not part of a TCP TLS/HTTPS A/B test.
 */
object Zapret2ProbeCatalog {
    const val PLAIN_TAG: String = "dppass:test-plain"
    val strategies: List<String> = listOf(
        "plain",
        "split-1",
        "split",
        "tlsrec-split",
        "fake-3",
        "fake-5",
        "disorder",
        "auto",
    )

    /** Dedicated test ingress; routes through the real protected exp dialer. */
    /** Fixed safe HTTPS destinations; no user-provided URL or redirect chain. */
    val targets: List<String> = listOf(
        "google_final",
        "youtube_home",
        "youtube_api_transport",
        "youtube_thumbnail",
    )

    /** User-visible diagnostic meaning for each allowlisted probe ID. */
    fun targetLabel(id: String): String = when (id) {
        "google_final" -> "www.google.com/ (HTML)"
        "youtube_home" -> "www.youtube.com/ (HTML)"
        "youtube_api_transport" -> "youtubei.googleapis.com/youtubei/v1/browse (TLS+HTTP only)"
        "youtube_thumbnail" -> "i.ytimg.com/ (JPEG)"
        else -> "unknown"
    }

    fun tag(strategy: String): String? =
        if (strategy !in strategies) null
        else if (strategy == "plain") PLAIN_TAG
        else "dppass:test-$strategy"

    fun experimentTag(strategy: String): String? =
        if (strategy == "plain" || strategy !in strategies) null
        else "dppass:exp-$strategy"
}
