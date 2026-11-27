package com.dpsmpx.dppass.app

/**
 * Session-scoped callback ledger and independent platform evidence gate.
 * Callback state is only a prerequisite; it is never proof of AP ownership
 * or request retirement. The observation provider must establish those facts
 * independently (not infer them from names, private IPs or callback state).
 */
internal class RootHotspotPlatformGate<R : Any>(
    private val request: RootHotspotLifecycle.Request,
    private val inventory: RootHotspotInventoryObserver,
    private val observe: () -> Observation?,
) {
    data class Observation(
        val request: RootHotspotLifecycle.Request,
        val state: RootHotspotInterfaceEvidence.PlatformState,
        val localOnlyInterfaces: Set<String>,
        val gateway: String?,
        val requestRetired: Boolean,
    )

    private enum class Phase { NEW, REQUESTED, STARTED, TERMINAL, UNCERTAIN }
    private data class Stamp(val phase: Phase, val revision: Long, val released: Boolean)
    private val monitor = Any()
    private var phase = Phase.NEW
    private var revision = 0L
    private var accepted: R? = null
    private var released = false

    fun dispatched(): Unit = synchronized(monitor) {
        check(phase == Phase.NEW)
        phase = Phase.REQUESTED
        revision++
    }

    fun started(resource: R): Unit = synchronized(monitor) {
        if (phase == Phase.REQUESTED) {
            accepted = resource
            phase = Phase.STARTED
        } else if (phase != Phase.STARTED || accepted !== resource) {
            phase = Phase.UNCERTAIN
        }
        revision++
    }

    fun terminal(): Unit = synchronized(monitor) {
        if (phase != Phase.NEW && phase != Phase.UNCERTAIN) phase = Phase.TERMINAL
        revision++
    }

    fun dispatchFailed(): Unit = synchronized(monitor) {
        phase = Phase.UNCERTAIN
        revision++
    }

    /** Record only successful close of the exact accepted reservation. */
    fun released(resource: R): Unit = synchronized(monitor) {
        if (accepted === resource) {
            released = true
            revision++
        }
    }

    private fun stamp() = synchronized(monitor) { Stamp(phase, revision, released) }

    private fun sample(): Observation? = observe()?.let { it.copy(localOnlyInterfaces = it.localOnlyInterfaces.toSet()) }
        ?.takeIf { it.request == request }

    fun discover(resource: R): RootHotspotInterfaceEvidence.Identity? = guarded(null) {
        val before = synchronized(monitor) {
            if (phase != Phase.STARTED || released || accepted !== resource) return@guarded null
            stamp()
        }
        val first = sample() ?: return@guarded null
        if (first.state != RootHotspotInterfaceEvidence.PlatformState.LOCAL_ONLY || first.requestRetired) return@guarded null
        val iface = first.localOnlyInterfaces.singleOrNull() ?: return@guarded null
        val gateway = first.gateway ?: return@guarded null
        val topology = inventory.stableInventory() ?: return@guarded null
        val index = topology.indexOf(iface) ?: return@guarded null
        val result = RootHotspotInterfaceEvidence.discover(
            RootHotspotAdmission.Session(request.generation, index, request.mode),
            topology, first.localOnlyInterfaces, gateway,
        )
        result.takeIf { first == sample() && before == stamp() }
    }

    fun stopped(identity: RootHotspotInterfaceEvidence.Identity?): Boolean = guarded(false) {
        val before = stamp()
        if (before.phase == Phase.STARTED && !before.released) return@guarded false
        val first = sample() ?: return@guarded false
        if (!first.requestRetired || first.localOnlyInterfaces.isNotEmpty() || first.gateway != null) return@guarded false
        if (first.state !in setOf(RootHotspotInterfaceEvidence.PlatformState.ABSENT,
                RootHotspotInterfaceEvidence.PlatformState.INACTIVE)) return@guarded false
        val topology = inventory.stableInventory() ?: return@guarded false
        // Without a discovered identity, require positive absence rather
        // than an inactive interface whose ownership cannot be established.
        val gone = if (identity == null) first.state == RootHotspotInterfaceEvidence.PlatformState.ABSENT
        else request.matches(identity.session) && RootHotspotInterfaceEvidence.stopped(identity,
            RootHotspotInterfaceEvidence.StopObservation(identity.session, true, first.state, topology))
        gone && first == sample() && before == stamp()
    }

    private inline fun <T> guarded(fallback: T, body: () -> T): T = try {
        body()
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        fallback
    } catch (_: Exception) {
        fallback
    }
}
