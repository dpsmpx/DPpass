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
    // The order of trainable methods also defines the current model layout.
    val siteTcpMethods: List<String> = listOf(
        "plain", "split-1", "split", "fake-3", "fake-5", "disorder", "tlsrec-split",
    )
    val siteQuicMethods: List<String> = listOf("plain", "fake-3", "fake-5")
    val strategies: List<String> = siteTcpMethods + "auto"

    // Additional profiles are explicit DPTS probes, not AUTO outputs.
    val scriptOnlyStrategies = listOf("split-2", "fake-2", "fake-4", "fake-8")
    val scriptOnlyQuicStrategies = listOf("fake-2", "fake-4", "fake-8")
    val allProbeStrategies = strategies + scriptOnlyStrategies
    val scriptTcpMethods: Set<String> = (siteTcpMethods + scriptOnlyStrategies).toSet()
    val scriptQuicMethods: Set<String> = (siteQuicMethods + scriptOnlyQuicStrategies).toSet()

    // Calibration requires a current TLS output. 'plain' is a
    // control, 'auto' is a selector, and script-only methods have no slot.
    val modelTcpMethods: List<String> = siteTcpMethods.filterNot { it == "plain" }
    // The diagnostic baseline is first in the UI, but last in the model.
    val modelQuicMethods: List<String> = siteQuicMethods.filterNot { it == "plain" } + "pass"
    val verifiedHtmlMethods: Set<String> = modelTcpMethods.toSet()
    val modelOutputs: Int = modelTcpMethods.size + modelQuicMethods.size
    val modelFormat: String = "dppass-strategy-mlp-v4:tcp=" +
        modelTcpMethods.joinToString(",") + ";quic=" + modelQuicMethods.joinToString(",")

    /** Dedicated test ingress; routes through the real protected exp dialer. */
    /** Fixed safe HTTPS destinations; no user-provided URL or redirect chain. */
    val targets: List<String> = listOf(
        "google_final",
        "google_search",
        "youtube_home",
        "youtube_api_transport",
        "youtube_api_ipv4",
        "youtube_thumbnail",
    )

    /** Independent, opt-in DNS comparison; not part of the 96-request autotest. */
    val dnsTargets: List<String> = listOf(
        "youtube_api_ipv4",
        "youtube_api_dns_cloudflare",
        "youtube_api_dns_google",
        "youtube_api_dns_quad9",
    )
    // The two modes that repeatedly delivered www.youtube.com HTML in
    // on-device tests. These controls never train a new global winner.
    val dnsStrategies: List<String> = listOf("fake-5", "tlsrec-split")

    /** TCP-baseline plus two prior candidate strategies; QUIC is plain UDP only. */
    val matrixStrategies: List<String> = listOf("plain", "fake-5", "tlsrec-split")
    val matrixProviders: List<String> = listOf("cloudflare", "google", "quad9")

    /** User-visible diagnostic meaning for each allowlisted probe ID. */
    fun targetLabel(id: String): String = when (id) {
        "google_final" -> "www.google.com/ (HTML)"
        "google_search" -> "www.google.com/search?q=site:example.com (HTML, not verified search results)"
        "youtube_home" -> "www.youtube.com/ (HTML)"
        "youtube_api_transport" -> "youtubei.googleapis.com/youtubei/v1/browse (TLS+HTTP, configured DNS)"
        "youtube_api_ipv4" -> "youtubei.googleapis.com (configured DNS, IPv4-only control)"
        "youtube_api_dns_cloudflare" -> "youtubei.googleapis.com via Cloudflare DoH (pinned 1.1.1.1)"
        "youtube_api_dns_google" -> "youtubei.googleapis.com via Google DoH (pinned 8.8.8.8)"
        "youtube_api_dns_quad9" -> "youtubei.googleapis.com via Quad9 DoH (pinned 9.9.9.9)"
        "youtube_thumbnail" -> "i.ytimg.com/ (JPEG)"
        else -> "unknown"
    }

    fun tag(strategy: String): String? =
        if (strategy !in allProbeStrategies) null
        else if (strategy == "plain") PLAIN_TAG
        else "dppass:test-$strategy"

    fun experimentTag(strategy: String): String? =
        if (strategy == "plain" || strategy !in allProbeStrategies) null
        else "dppass:exp-$strategy"
}
