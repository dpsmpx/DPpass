package com.dpsmpx.dppass.app

/** Read-only diagnostic model. Never initializes directories, acquires a
 * claim or dispatches Wi-Fi. Global observations do not authorize activation. */
internal class RootHotspotReadiness(private val root: RootHotspotRootAccess) {
    enum class Check { ROOT_BASELINE, CLAIM_ABSENT, TETHER_IDLE, INVENTORY }
    data class Report(val passed: Set<Check>, val failed: Set<Check>) {
        val observationsReady: Boolean get() = failed.isEmpty()
        // Independent ownership/offload and physical acceptance are not
        // provided by this diagnostic.
        val activationAllowed: Boolean get() = false
    }

    fun inspect(): Report {
        val passed = linkedSetOf<Check>()
        if (root.baseline()) {
            passed += Check.ROOT_BASELINE
            if (root.inspect() == RootHotspotRootAccess.ClaimState.Absent) passed += Check.CLAIM_ABSENT
            if (root.tethering().stable()?.idle == true) passed += Check.TETHER_IDLE
            if (root.inventory().stableInventory() != null) passed += Check.INVENTORY
        }
        return Report(passed.toSet(), Check.entries.toSet() - passed)
    }
}
