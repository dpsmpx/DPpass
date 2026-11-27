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
    private val firewall: RootHotspotFirewallEvidence.Observer,
    private val routing: RootHotspotRoutingEvidence.Observer,
) : RootHotspotServiceRuntime.Egress<R> {
    interface Driver<R : Any> {
        fun platformSafe(resource: R, identity: RootHotspotInterfaceEvidence.Identity): Boolean
        fun verifyGuard(plan: RootHotspotNetworkPlan): Boolean
        fun startEngine(resource: R, plan: RootHotspotNetworkPlan): Boolean
        fun evidence(plan: RootHotspotNetworkPlan): RootHotspotAdmission.Evidence
        fun verifyAttached(plan: RootHotspotNetworkPlan): Boolean
        fun engineHealthy(plan: RootHotspotNetworkPlan): Boolean = false
        fun stopEngine(plan: RootHotspotNetworkPlan): Boolean
        fun verifyEngineStopped(plan: RootHotspotNetworkPlan): Boolean
    }

    private enum class State { NEW, GUARD_ATTEMPTED, ENGINE_ATTEMPTED, PREPARED, ATTACH_ATTEMPTED, READY, STOPPING }
    private var state = State.NEW
    private var plan: RootHotspotNetworkPlan? = null
    private var resource: R? = null
    private var guardAttempted = false
    private var engineAttempted = false
    private var attachAttempted = false
    private var detached = false

    private fun refused() = RootHotspotAdmission.Evidence(false, null, null, null, null, null, null)

    override fun prepare(resource: R, identity: RootHotspotInterfaceEvidence.Identity,
                         owned: (String) -> Boolean): RootHotspotAdmission.Evidence {
        check(state == State.NEW)
        val selected = planFor(identity)
        require(selected.identity == identity)
        this.resource = resource
        plan = selected
        if (!driver.platformSafe(resource, identity)) return refused()
        // A known failed read-only precheck does not authorize deletion
        // of a preexisting route in the reserved numeric slot.
        if (!owned(selected.vacancy())) return refused()
        state = State.GUARD_ATTEMPTED
        guardAttempted = true
        if (!owned(selected.guard()) || !firewall.stable(selected.firewallExpected(false)) ||
            !routing.stable(selected, false) || !driver.verifyGuard(selected)) return refused()
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
            !firewall.stable(selected.firewallExpected(false)) ||
            !routing.stable(selected, false) || !driver.verifyGuard(selected) ||
            RootHotspotAdmission.refusal(identity.session, driver.evidence(selected)) != null) return false
        state = State.ATTACH_ATTEMPTED
        attachAttempted = true
        if (!owned(selected.attach()) || !firewall.stable(selected.firewallExpected(true)) ||
            !routing.stable(selected, true) || !driver.verifyAttached(selected)) return false
        state = State.READY
        return true
    }

    override fun verifyReady(session: RootHotspotAdmission.Session): Boolean {
        if (state != State.READY) return false
        val selected = plan ?: return false
        if (selected.identity.session != session) return false
        val currentResource = resource ?: return false
        return driver.platformSafe(currentResource, selected.identity) &&
            driver.engineHealthy(selected) &&
            firewall.stable(selected.firewallExpected(true)) &&
            routing.stable(selected, true) &&
            RootHotspotAdmission.refusal(session, driver.evidence(selected)) == null &&
            driver.verifyAttached(selected) &&
            driver.platformSafe(currentResource, selected.identity) &&
            driver.engineHealthy(selected)
    }

    override fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean): Boolean {
        val selected = plan ?: return true
        require(selected.identity == identity)
        state = State.STOPPING
        // A failed detach must still attempt engine stop. The outer
        // controller independently closes the AP even on exception.
        detached = !attachAttempted
        try {
            if (attachAttempted) detached = owned(selected.detach()) &&
                firewall.stable(selected.firewallExpected(false)) && routing.stable(selected, false)
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
        check(state == State.STOPPING && !engineAttempted && detached)
        return if (guardAttempted) selected.retire() else ":"
    }
}
