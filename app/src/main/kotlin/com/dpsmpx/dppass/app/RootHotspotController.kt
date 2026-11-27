package com.dpsmpx.dppass.app

/**
 * Single lifecycle controller for the experimental ROOT hotspot.
 * Worker callbacks are bounded and must independently prove AP identity,
 * guard/egress readiness, and request retirement. Platform callbacks only
 * touch the reservation. No Android service registration or activation.
 */
internal class RootHotspotController<R : Any>(
    private val release: (R) -> Unit,
    private val execute: (String) -> Boolean,
) {
    private val lifecycle = RootHotspotLifecycle()

    fun snapshot(): RootHotspotLifecycle.Snapshot = lifecycle.snapshot()

    fun start(
        request: RootHotspotLifecycle.Request,
        claim: RootHotspotClaim,
        timeoutMillis: Long,
        dispatch: (RootHotspotReservation<R>) -> Unit,
        discover: (R) -> RootHotspotInterfaceEvidence.Identity?,
        prepare: (R, RootHotspotInterfaceEvidence.Identity, (String) -> Boolean) -> RootHotspotAdmission.Evidence,
        attach: (RootHotspotInterfaceEvidence.Identity, (String) -> Boolean) -> Boolean,
        stopEgress: (RootHotspotInterfaceEvidence.Identity?, (String) -> Boolean) -> Boolean,
        verifyStopped: (RootHotspotInterfaceEvidence.Identity?) -> Boolean,
        cleanup: (RootHotspotInterfaceEvidence.Identity) -> String,
    ): RootHotspotLifecycle.StartResult {
        require(timeoutMillis > 0)
        val lease = RootHotspotClaimLease<R>(claim, execute)
        val reservation = RootHotspotReservationOwner(release)
        var identity: RootHotspotInterfaceEvidence.Identity? = null
        var prepared = false
        return lifecycle.startPending(request, prepare = { bind ->
            if (!lease.reserveAndRequest(reservation.pending, dispatch)) false
            else {
                val resource = reservation.take(timeoutMillis)
                val found = discover(resource)
                if (found == null || !request.matches(found.session)) false
                else {
                    identity = found
                    if (!lease.bind(found) || !bind(found.session)) false
                    else {
                        // Mark before any mutation; partial preparation needs
                        // egress stop and exact guarded rollback as well.
                        prepared = true
                        RootHotspotAdmission.refusal(found.session,
                            prepare(resource, found, lease::owned)) == null
                    }
                }
            }
        }, attach = {
            attach(checkNotNull(identity), lease::owned)
        }, shutdown = {
            lease.beginStopping()
            RootHotspotShutdown.run(
                stopEgress = { !prepared || stopEgress(identity, lease::cleanupOwned) },
                closeAndVerifyAccessPoint = { reservation.closeAndVerify { verifyStopped(identity) } },
                retireGuards = {
                    // Even ambiguous binding can be retired only after the
                    // exact record and independent postconditions are checked.
                    val body = if (prepared) cleanup(checkNotNull(identity)) else ":"
                    lease.retire({ !reservation.pending.cleanupStatus().unresolved && verifyStopped(identity) }, body)
                },
            )
        })
    }

    fun stop(request: RootHotspotLifecycle.Request): RootHotspotLifecycle.StopResult = lifecycle.stop(request)
}
