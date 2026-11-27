package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.CompiledConfig

/** Bridges the shared-engine owner into the existing egress coordinator.
 * The platform evidence provider remains mandatory and independent;
 * starting Xray is not proof of client egress, DNS confinement or offload.
 * A real Android helper and authoritative evidence are still required. */
internal class RootHotspotEngineDriver<R : Any>(
    private val engine: RootHotspotEngineOwner,
    private val config: (RootHotspotAdmission.Session) -> CompiledConfig?,
    private val acquire: (R, RootHotspotNetworkPlan) -> RootHotspotEngineOwner.Tun,
    private val proof: Proof<R>,
) : RootHotspotEgressCoordinator.Driver<R> {
    interface Proof<R : Any> {
        fun platformSafe(resource: R, identity: RootHotspotInterfaceEvidence.Identity): Boolean
        fun guard(plan: RootHotspotNetworkPlan): Boolean
        fun evidence(plan: RootHotspotNetworkPlan): RootHotspotAdmission.Evidence
        fun attached(plan: RootHotspotNetworkPlan): Boolean
    }

    private var attempted = false
    private var selected: RootHotspotNetworkPlan? = null
    private var engineAttempted = false
    private var started = false

    override fun platformSafe(resource: R, identity: RootHotspotInterfaceEvidence.Identity): Boolean =
        proof.platformSafe(resource, identity)

    override fun verifyGuard(plan: RootHotspotNetworkPlan): Boolean = proof.guard(plan)

    override fun startEngine(resource: R, plan: RootHotspotNetworkPlan): Boolean {
        check(!attempted)
        attempted = true
        selected = plan
        val compiled = config(plan.identity.session) ?: return false
        engineAttempted = true
        started = engine.start(compiled) { acquire(resource, plan) }
        return started
    }

    override fun evidence(plan: RootHotspotNetworkPlan): RootHotspotAdmission.Evidence {
        if (selected !== plan || !started) {
            return RootHotspotAdmission.Evidence(false, null, null, null, null, null, null)
        }
        return proof.evidence(plan)
    }

    override fun engineHealthy(plan: RootHotspotNetworkPlan): Boolean =
        selected === plan && started && engine.healthy()

    override fun verifyAttached(plan: RootHotspotNetworkPlan): Boolean =
        selected === plan && started && proof.attached(plan)

    override fun stopEngine(plan: RootHotspotNetworkPlan): Boolean {
        if (selected !== plan) return false
        started = false
        return !engineAttempted || engine.stop()
    }

    override fun verifyEngineStopped(plan: RootHotspotNetworkPlan): Boolean =
        selected === plan && !started && (!engineAttempted || engine.retired())
}
