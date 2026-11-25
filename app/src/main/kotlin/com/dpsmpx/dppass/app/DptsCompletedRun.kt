package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsPlan
import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleAttempt
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe

/** In-memory evidence belongs to one exact editor source and native session. */
internal class DptsCompletedRun private constructor(
    private val source: String,
    val plan: DptsPlan,
    val rows: List<Zapret2GoogleAttempt>,
    val network: String,
    private val handle: Long,
    val generation: Long,
) {
    // Native supervised calibration supports only these two network heads.
    val trainingNetworkSupported: Boolean get() = network == "MOBILE" || network == "WIFI"

    fun matchesSource(currentSource: String): Boolean = source == currentSource

    fun matches(currentSource: String, currentNetwork: String, currentHandle: Long?,
        currentGeneration: Long?): Boolean =
        matchesSource(currentSource) && network == currentNetwork &&
            handle == currentHandle && generation == currentGeneration

    companion object {
        fun capture(source: String, plan: DptsPlan, prepared: Zapret2GoogleProbe,
            rows: List<Zapret2GoogleAttempt>, network: String, handle: Long,
            generation: Long): DptsCompletedRun? =
            if (generation >= 0 && DptsScript.completeEvidence(plan, prepared, rows))
                DptsCompletedRun(source, plan.copy(probes = plan.probes.toList()),
                    rows.toList(), network, handle, generation)
            else null
    }
}
