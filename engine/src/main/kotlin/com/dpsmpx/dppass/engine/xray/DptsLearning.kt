package com.dpsmpx.dppass.engine.xray

/**
 * Only independently verified HTML HTTPS on the same two public IPs
 * can teach a strategy preference. API 4xx, redirects, handshake-only,
 * QUIC and cached image prefixes are NOT usable training evidence.
 *
 * A DPTS script cannot choose its own labels; only native probe results
 * collected for its finite, compiler-validated target matrix are inspected.
 */
object DptsLearning {
    val trainable = setOf("split-1", "split", "tlsrec-split",
        "fake-3", "fake-5", "disorder")

    fun confirmedWinners(plan: DptsPlan, rows: List<Zapret2GoogleAttempt>): List<String> {
        if (!plan.observeLearning || plan.suite != null ||
            plan.host != "www.youtube.com" ||
            rows.size != plan.probes.size || plan.probes.size > DptsScript.MAX_PROBES)
            return emptyList()

        fun on(ip: Int, method: String): List<Zapret2GoogleProbe>? {
            val slots = (1..Zapret2SiteSearch.ATTEMPTS).map { attempt ->
                val indices = plan.probes.indices.filter { i ->
                    val spec = plan.probes[i]
                    spec.ipIndex == ip && spec.attempt == attempt &&
                        spec.phase == "https" && spec.protocol == "h1" &&
                        spec.method == method
                }
                if (indices.size != 1) return null
                val idx = indices.single()
                val r = rows[idx]
                if (r.methodName() != method || r.attempt != attempt ||
                    r.target != plan.probes[idx].target ||
                    r.result.ipIndex != ip || r.result.protocol != "h1")
                    return null
                r.result
            }
            return slots
        }

        fun proof(result: Zapret2GoogleProbe) =
            result.outcome == "ok" && result.tlsStage == "tls_verified" &&
                result.alpn == "http/1.1" && result.httpStatus in 200..299 &&
                result.bodyBytes >= 128

        val ipIndices = (0..1).toList()
        if (ipIndices.any { ip ->
                val baseline = on(ip, "plain") ?: return@any true
                baseline.any(::proof)
            }) return emptyList()

        return trainable.filter { method ->
            ipIndices.all { ip -> (on(ip, method) ?: return@all false).all(::proof) }
        }
    }

    private fun Zapret2GoogleAttempt.methodName(): String = strategy
}
