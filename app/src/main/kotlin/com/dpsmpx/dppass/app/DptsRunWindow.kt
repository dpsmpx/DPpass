package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.Zapret2SiteSearch

/** Conservative monotonic window, beginning before the DNS preparation. */
internal class DptsRunWindow(private val startedAt: Long, dnsTimeoutMs: Int) {
    private val limitMs = minOf(Zapret2SiteSearch.TTL_MS,
        DptsScript.MAX_BUDGET_MS + dnsTimeoutMs.toLong())

    fun canFinish(now: Long): Boolean =
        startedAt >= 0 && now >= startedAt && now - startedAt < limitMs

    fun canStart(now: Long, timeoutMs: Int): Boolean =
        timeoutMs in 1000..12000 && canFinish(now) &&
            timeoutMs.toLong() < limitMs - (now - startedAt)

    companion object {
        private val executionErrors = setOf("engine_off", "dns_not_prepared",
            "invalid_target", "invalid_strategy", "invalid_index", "invalid_timeout",
            "unsupported", "contract_error")
        fun invalidExecution(outcome: String): Boolean = outcome in executionErrors
    }
}
