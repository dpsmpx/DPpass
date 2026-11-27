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
        val reservationOwner = RootHotspotReservationOwner(release)

        return lifecycle.start(
            session,
            prepare = {
                request(reservationOwner.pending)
                prepare(reservationOwner.take(timeoutMillis))
            },
            attach = { attach(reservationOwner.resource()) },
            shutdown = {
                RootHotspotShutdown.run(
                    stopEgress = stopEgress,
                    closeAndVerifyAccessPoint = { reservationOwner.closeAndVerify(verifyStopped) },
                    retireGuards = retireGuards,
                )
            },
        )
    }

    fun stop(session: RootHotspotAdmission.Session): RootHotspotLifecycle.StopResult =
        lifecycle.stop(session)
}
