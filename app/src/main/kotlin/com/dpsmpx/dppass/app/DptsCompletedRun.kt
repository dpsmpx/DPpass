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
    private val session: DptsSession,
) {
    val network: String get() = session.network
    val generation: Long get() = session.generation

    // Native supervised calibration supports only these two network heads.
    val trainingNetworkSupported: Boolean get() = network == "MOBILE" || network == "WIFI"

    fun matches(currentSource: String, currentSession: DptsSession?): Boolean =
        source == currentSource && session == currentSession

    companion object {
        fun capture(source: String, plan: DptsPlan, prepared: Zapret2GoogleProbe,
            rows: List<Zapret2GoogleAttempt>, session: DptsSession?): DptsCompletedRun? =
            if (session != null && DptsScript.completeEvidence(plan, prepared, rows))
                DptsCompletedRun(source, plan.copy(probes = plan.probes.toList()),
                    rows.toList(), session)
            else null
    }
}
