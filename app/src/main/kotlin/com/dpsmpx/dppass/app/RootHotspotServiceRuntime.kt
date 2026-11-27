package com.dpsmpx.dppass.app

/**
 * One service request assembled from the existing ROOT access and controller.
 * Factory/constructor is side-effect free. The preflight never grants
 * ownership; the controller still acquires the persistent claim under flock.
 * A platform implementation and egress implementation must be independently
 * validated before this runtime can be used by an Android service.
 */
internal class RootHotspotServiceRuntime<R : Any>(
    private val request: RootHotspotLifecycle.Request,
    private val root: RootHotspotRootAccess,
    private val processIdentity: () -> RootOwnerIdentity,
    private val slot: RootHotspotNetworkSlot,
    private val accessPoint: AccessPoint<R>,
    private val egress: Egress<R>,
    private val timeoutMillis: Long = 20_000,
) : RootHotspotServiceOwner.Runtime {
    interface AccessPoint<R : Any> {
        fun dispatch(pending: RootHotspotReservation<R>)
        fun release(resource: R)
        fun discover(resource: R): RootHotspotInterfaceEvidence.Identity?
        fun verifyStopped(identity: RootHotspotInterfaceEvidence.Identity?): Boolean
    }

    interface Egress<R : Any> {
        /** Side-effect-free injection of the exact request claim. */
        fun bindPendingClaim(claim: RootHotspotClaim) = Unit
        fun prepare(resource: R, identity: RootHotspotInterfaceEvidence.Identity,
                    owned: (String) -> Boolean): RootHotspotAdmission.Evidence
        fun attach(identity: RootHotspotInterfaceEvidence.Identity, owned: (String) -> Boolean): Boolean
        fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean): Boolean
        fun cleanup(identity: RootHotspotInterfaceEvidence.Identity): String
        fun verifyReady(session: RootHotspotAdmission.Session): Boolean = false
    }

    private val controller = RootHotspotController<R>(accessPoint::release, root::execute)
    private var attempted = false
    private var pendingClaim: RootHotspotClaim? = null
    // ServiceOwner serializes calls to start/stop. No live callbacks may call
    // these directly. Controller retains its own exact cleanup closure.
    init { require(timeoutMillis in 1..60_000) }

    override fun snapshot(): RootHotspotLifecycle.Snapshot = controller.snapshot()

    override fun start(): RootHotspotLifecycle.StartResult {
        check(!attempted) { "ROOT hotspot runtime is one-shot" }
        attempted = true
        if (!root.initialize() || !root.baseline() ||
            root.inspect() != RootHotspotRootAccess.ClaimState.Absent) {
            return RootHotspotLifecycle.StartResult.REFUSED
        }
        val owner = root.owner(processIdentity()) ?: return RootHotspotLifecycle.StartResult.REFUSED
        val claim = RootHotspotClaim.pending(request.generation, request.mode, owner, slot)
        pendingClaim = claim
        egress.bindPendingClaim(claim)
        return controller.start(request, claim, timeoutMillis,
            dispatch = accessPoint::dispatch,
            discover = accessPoint::discover,
            prepare = egress::prepare,
            attach = egress::attach,
            stopEgress = egress::stop,
            verifyStopped = accessPoint::verifyStopped,
            cleanup = egress::cleanup,
        )
    }

    override fun verifyReady(): Boolean {
        val before = controller.snapshot()
        val session = before.session ?: return false
        if (before.state != RootHotspotLifecycle.State.READY || before.request != request ||
            !request.matches(session)) return false
        // Construct the exact bound handle without running its bind script.
        val bound = pendingClaim?.bind(session)?.claim ?: return false
        return root.execute(bound.confirm()) && egress.verifyReady(session) &&
            root.execute(bound.confirm()) && controller.snapshot() == before
    }

    override fun stop(): RootHotspotLifecycle.StopResult {
        val state = controller.snapshot()
        if (state.state == RootHotspotLifecycle.State.IDLE) {
            // A thrown preflight or a confirmed rollback can leave no
            // controller owner. Do not clear uncertain persistent metadata.
            return if (root.inspect() == RootHotspotRootAccess.ClaimState.Absent)
                RootHotspotLifecycle.StopResult.STOPPED
            else RootHotspotLifecycle.StopResult.CLEANUP_PENDING
        }
        return controller.stop(request)
    }
}
