package com.dpsmpx.dppass.app

/**
 * Compose independent platform observations. The owner evidence provider
 * must be authoritative for this exact request: global tether state, UID,
 * callback delivery and interface names alone are not owner evidence.
 * No production provider is assumed or fabricated.
 */
internal class RootHotspotPlatformObservationSource(
    private val request: RootHotspotLifecycle.Request,
    private val tether: RootHotspotTetherObserver,
    private val inventory: RootHotspotInventoryObserver,
    private val ownerEvidence: () -> OwnerEvidence?,
) {
    sealed interface OwnerEvidence {
        val request: RootHotspotLifecycle.Request
        data class Active(
            override val request: RootHotspotLifecycle.Request,
            val identity: RootHotspotInterfaceEvidence.Identity,
        ) : OwnerEvidence
        /** Positive request retirement; identity is null only when platform
         * independently establishes that no AP was created by this request. */
        data class Retired(
            override val request: RootHotspotLifecycle.Request,
            val identity: RootHotspotInterfaceEvidence.Identity?,
        ) : OwnerEvidence
    }

    /** Must run immediately before dispatch while holding the reserved ROOT
     * claim. This checks global baseline, not exclusion of future OS writers. */
    fun idleBeforeDispatch(): Boolean = guarded(false) {
        val first = tether.stable() ?: return@guarded false
        if (!first.idle || inventory.stableInventory() == null) return@guarded false
        first == tether.stable()
    }

    fun observe(): RootHotspotPlatformGate.Observation? = guarded(null) {
        val owner = ownerEvidence()?.takeIf { it.request == request } ?: return@guarded null
        val first = tether.stable() ?: return@guarded null
        val topology = inventory.stableInventory() ?: return@guarded null
        val result = when (owner) {
            is OwnerEvidence.Active -> active(owner.identity, first, topology)
            is OwnerEvidence.Retired -> retired(owner.identity, first, topology)
        } ?: return@guarded null
        result.takeIf { first == tether.stable() && owner == ownerEvidence() }
    }

    private fun active(identity: RootHotspotInterfaceEvidence.Identity,
                       state: RootHotspotTetherState.Snapshot,
                       topology: RootHotspotInterfaceEvidence.Inventory): RootHotspotPlatformGate.Observation? {
        if (!request.matches(identity.session) || state.isolatedLocalOnly != identity.name) return null
        if (RootHotspotInterfaceEvidence.discover(identity.session, topology,
                setOf(identity.name), identity.gateway) != identity) return null
        return RootHotspotPlatformGate.Observation(request, RootHotspotInterfaceEvidence.PlatformState.LOCAL_ONLY,
            setOf(identity.name), identity.gateway, false)
    }

    private fun retired(identity: RootHotspotInterfaceEvidence.Identity?,
                        state: RootHotspotTetherState.Snapshot,
                        topology: RootHotspotInterfaceEvidence.Inventory): RootHotspotPlatformGate.Observation? {
        if (!state.idle) return null
        val platformState = if (identity == null) RootHotspotInterfaceEvidence.PlatformState.ABSENT else {
            if (!request.matches(identity.session)) return null
            // Missing from tethering is not itself proof of a missing
            // kernel interface. Require consistent independent topology.
            val candidate = when (state.interfaces[identity.name]) {
                null -> RootHotspotInterfaceEvidence.PlatformState.ABSENT
                RootHotspotTetherState.State.AVAILABLE, RootHotspotTetherState.State.UNAVAILABLE ->
                    RootHotspotInterfaceEvidence.PlatformState.INACTIVE
                else -> return null
            }
            if (!RootHotspotInterfaceEvidence.stopped(identity, RootHotspotInterfaceEvidence.StopObservation(
                    identity.session, true, candidate, topology))) return null
            candidate
        }
        return RootHotspotPlatformGate.Observation(request, platformState, emptySet(), null, true)
    }

    private inline fun <T> guarded(fallback: T, block: () -> T): T = try {
        block()
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        fallback
    } catch (_: Exception) { fallback }
}
