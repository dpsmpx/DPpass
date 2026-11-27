package com.dpsmpx.dppass.app

/**
 * Bind one concrete egress to the exact pending claim issued by Runtime.
 * prepare is called only after controller-confirmed binding; constructing
 * a handle alone never grants ROOT authority. Factory is side-effect free.
 */
internal class RootHotspotBoundEgress<R : Any>(
    private val request: RootHotspotLifecycle.Request,
    private val assemble: (RootHotspotClaim, RootHotspotNetworkPlan) -> RootHotspotServiceRuntime.Egress<R>,
) : RootHotspotServiceRuntime.Egress<R> {
    private var pending: RootHotspotClaim? = null
    private var attempted = false
    private var selected: RootHotspotInterfaceEvidence.Identity? = null
    private var delegate: RootHotspotServiceRuntime.Egress<R>? = null

    override fun bindPendingClaim(claim: RootHotspotClaim) {
        check(pending == null && !attempted)
        require(claim.pendingFor(request))
        pending = claim
    }

    override fun prepare(resource: R, identity: RootHotspotInterfaceEvidence.Identity,
                         owned: (String) -> Boolean): RootHotspotAdmission.Evidence {
        check(!attempted)
        attempted = true
        require(request.matches(identity.session))
        val bound = checkNotNull(pending).bind(identity.session).claim
        val plan = bound.networkPlan(identity)
        selected = identity
        val actual = assemble(bound, plan)
        delegate = actual
        return actual.prepare(resource, identity, owned)
    }

    override fun attach(identity: RootHotspotInterfaceEvidence.Identity, owned: (String) -> Boolean): Boolean {
        require(selected == identity)
        return checkNotNull(delegate).attach(identity, owned)
    }

    override fun verifyReady(session: RootHotspotAdmission.Session): Boolean =
        selected?.session == session && delegate?.verifyReady(session) == true

    override fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean): Boolean {
        val actual = delegate ?: return true // side-effect-free assembly did not complete
        require(selected == identity)
        return actual.stop(identity, owned)
    }

    override fun cleanup(identity: RootHotspotInterfaceEvidence.Identity): String {
        val actual = delegate ?: return ":"
        require(selected == identity)
        return actual.cleanup(identity)
    }
}
