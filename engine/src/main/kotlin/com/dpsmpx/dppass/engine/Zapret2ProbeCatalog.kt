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

    fun tag(strategy: String): String? =
        if (strategy !in strategies) null
        else if (strategy == "plain") PLAIN_TAG
        else "dppass:exp-$strategy"
}
