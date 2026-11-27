package com.dpsmpx.dppass.app

/**
 * Concrete orchestration of the network plan and an independently verified
 * private TUN engine. A platform-specific engine/proof implementation is
 * required; never synthesize readiness from shell exit status.
 * All methods run on the exclusive service worker.
 */
internal class RootHotspotEgressCoordinator<R : Any>(
    private val planFor: (RootHotspotInterfaceEvidence.Identity) -> RootHotspotNetworkPlan,
    private val driver: Driver<R>,
) : RootHotspotServiceRuntime.Egress<R> {
    interface Driver<R : Any> {
        fun platformSafe(resource: R, identity: RootHotspotInterfaceEvidence.Identity): Boolean
        fun verifyGuard(plan: RootHotspotNetworkPlan): Boolean
        fun startEngine(resource: R, plan: RootHotspotNetworkPlan): Boolean
        fun evidence(plan: RootHotspotNetworkPlan): RootHotspotAdmission.Evidence
        fun verifyAttached(plan: RootHotspotNetworkPlan): Boolean
        fun stopEngine(plan: RootHotspotNetworkPlan): Boolean
        fun verifyEngineStopped(plan: RootHotspotNetworkPlan): Boolean
    }

    private enum class State { NEW, GUARD_ATTEMPTED, ENGINE_ATTEMPTED, PREPARED, ATTACH_ATTEMPTED, READY, STOPPING }
    private var state = State.NEW
    private var plan: RootHotspotNetworkPlan? = null
    private var resource: R? = null
    private var engineAttempted = false
    private var attachAttempted = false

    private fun refused() = RootHotspotAdmission.Evidence(false, null, null, null, null, null, null)

    override fun prepare(resource: R, identity: RootHotspotInterfaceEvidence.Identity,
                         owned: (String) -> Boolean): RootHotspotAdmission.Evidence {
        check(state == State.NEW)
        val selected = planFor(identity)
        require(selected.identity == identity)
        this.resource = resource
        plan = selected
        if (!driver.platformSafe(resource, identity)) return refused()
        state = State.GUARD_ATTEMPTED
        if (!owned(selected.guard()) || !driver.verifyGuard(selected)) return refused()
        state = State.ENGINE_ATTEMPTED
        engineAttempted = true
        if (!driver.startEngine(resource, selected)) return refused()
        val evidence = driver.evidence(selected)
        if (RootHotspotAdmission.refusal(identity.session, evidence) == null) state = State.PREPARED
        return evidence
    }

    override fun attach(identity: RootHotspotInterfaceEvidence.Identity, owned: (String) -> Boolean): Boolean {
        check(state == State.PREPARED)
        val selected = checkNotNull(plan)
        require(selected.identity == identity)
        if (!driver.platformSafe(checkNotNull(resource), identity) ||
            !driver.verifyGuard(selected) ||
            RootHotspotAdmission.refusal(identity.session, driver.evidence(selected)) != null) return false
        state = State.ATTACH_ATTEMPTED
        attachAttempted = true
        if (!owned(selected.attach()) || !driver.verifyAttached(selected)) return false
        state = State.READY
        return true
    }

    override fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean): Boolean {
        val selected = plan ?: return true
        require(selected.identity == identity)
        state = State.STOPPING
        // A failed detach must still attempt engine stop. The outer
        // controller independently closes the AP even on exception.
        var detached = !attachAttempted
        try {
            if (attachAttempted) detached = owned(selected.detach())
        } finally {
            if (engineAttempted && driver.stopEngine(selected) && driver.verifyEngineStopped(selected)) {
                engineAttempted = false
            }
        }
        return detached && !engineAttempted
    }

    override fun cleanup(identity: RootHotspotInterfaceEvidence.Identity): String {
        val selected = plan ?: return ":"
        require(selected.identity == identity)
        check(state == State.STOPPING && !engineAttempted)
        return selected.retire()
    }
}
