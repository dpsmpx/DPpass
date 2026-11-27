package com.dpsmpx.dppass.app

/**
 * D-120: compose the session owner, asynchronous AP acquisition and ordered
 * shutdown. This is an experimental orchestration contract, not an Android
 * service. The caller supplies a discovered session identity, bounded worker
 * operations and the cross-process ROOT lock.
 *
 * All operations are scoped to this exact session. stopEgress, release and
 * retireGuards must be retryable. verifyStopped must independently prove that
 * the platform request cannot create another AP and the owned AP is absent;
 * a callback or successful reservation.close alone is insufficient.
 */
internal class RootHotspotSessionRunner<R : Any>(private val release: (R) -> Unit) {
    private val lifecycle = RootHotspotLifecycle()

    fun snapshot(): RootHotspotLifecycle.Snapshot = lifecycle.snapshot()

    fun start(
        session: RootHotspotAdmission.Session,
        timeoutMillis: Long,
        request: (RootHotspotReservation<R>) -> Unit,
        prepare: (R) -> RootHotspotAdmission.Evidence,
        attach: (R) -> Boolean,
        stopEgress: () -> Boolean,
        verifyStopped: () -> Boolean,
        retireGuards: () -> Boolean,
    ): RootHotspotLifecycle.StartResult {
        require(timeoutMillis > 0)
        val pending = RootHotspotReservation(release)
        // Accessed only by the exclusive lifecycle operation. If release
        // throws, retain this exact identity for the next shutdown attempt.
        var taken: R? = null

        fun closeAndVerify(): Boolean {
            var failure: Throwable? = null
            try {
                taken?.let {
                    release(it)
                    taken = null
                }
            } catch (cause: Throwable) {
                failure = cause
            }
            try {
                pending.close()
            } catch (cause: Throwable) {
                val original = failure
                if (original == null) failure = cause
                else if (original !== cause) original.addSuppressed(cause)
            }
            failure?.let { throw it }
            if (pending.cleanupStatus().unresolved) return false
            // The proof is session-scoped and must cover late platform events.
            return verifyStopped() && !pending.cleanupStatus().unresolved
        }

        return lifecycle.start(
            session,
            prepare = {
                request(pending)
                val reservation = pending.take(timeoutMillis)
                taken = reservation
                prepare(reservation)
            },
            attach = { attach(checkNotNull(taken)) },
            shutdown = {
                RootHotspotShutdown.run(
                    stopEgress = stopEgress,
                    closeAndVerifyAccessPoint = ::closeAndVerify,
                    retireGuards = retireGuards,
                )
            },
        )
    }

    fun stop(session: RootHotspotAdmission.Session): RootHotspotLifecycle.StopResult =
        lifecycle.stop(session)
}
