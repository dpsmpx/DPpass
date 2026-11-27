package com.dpsmpx.dppass.app

/**
 * Experimental one-shot bridge between persistent ROOT ownership and an
 * asynchronous AP request. Confined to one serialized lifecycle worker;
 * platform callbacks may only use the separate reservation object.
 * A false/exceptional mutation is ambiguous, never permission to proceed.
 * No Android service activation or automatic recovery here.
 */
internal class RootHotspotClaimLease<R : Any>(
    private val pending: RootHotspotClaim,
    private val execute: (String) -> Boolean,
) {
    enum class State { NEW, UNCONFIRMED, RESERVED, REQUESTED, BOUND, RETIRED }
    var state = State.NEW
        private set
    private var candidate: RootHotspotClaim? = null
    private var bound: RootHotspotClaim? = null

    /** Mark ambiguous before execution so a thrown timeout cannot be retried
     * as a fresh request. No AP dispatch unless acquisition returned success. */
    fun reserveAndRequest(reservation: RootHotspotReservation<R>,
                          dispatch: (RootHotspotReservation<R>) -> Unit): Boolean {
        check(state == State.NEW)
        state = State.UNCONFIRMED
        if (!execute(pending.acquire())) return false
        state = State.RESERVED
        // Recheck ownership immediately before handing control to Android.
        if (!execute(pending.confirm())) {
            state = State.UNCONFIRMED
            return false
        }
        state = State.REQUESTED
        dispatch(reservation)
        return true
    }

    /** Identity must come from independent positive platform/inventory
     * discovery, not merely from the reservation callback. */
    fun bind(identity: RootHotspotInterfaceEvidence.Identity): Boolean {
        check(state == State.REQUESTED)
        val binding = pending.bind(identity.session)
        candidate = binding.claim
        state = State.UNCONFIRMED
        if (!execute(binding.script)) return false
        bound = binding.claim
        state = State.BOUND
        return true
    }

    /** Only a confirmed bound claim admits privileged work. */
    fun owned(body: String): Boolean {
        check(state == State.BOUND)
        return execute(checkNotNull(bound).owned(body))
    }

    /**
     * The lifecycle worker must stop egress, close the reservation and
     * independently prove request/AP retirement before this call. A callback
     * failure retains the exact candidate handles. Neither a missing record
     * nor an unavailable command is permission to clear local ownership.
     * The claim script checks the exact record again under the ROOT lock.
     */
    fun retire(verifyStopped: () -> Boolean, cleanupBound: String): Boolean {
        if (state == State.RETIRED) return true
        check(state != State.NEW)
        if (!verifyStopped()) return false
        val active = bound ?: candidate?.takeIf { execute(it.confirm()) }
        val handle = active ?: pending.takeIf { execute(it.confirm()) } ?: return false
        // No privileged network work is admitted while unbound. Do not
        // execute a bound cleanup body on an unbound record.
        val cleanup = if (active != null) cleanupBound else ":"
        if (!execute(handle.releaseAfter(cleanup))) return false
        state = State.RETIRED
        return true
    }
}
