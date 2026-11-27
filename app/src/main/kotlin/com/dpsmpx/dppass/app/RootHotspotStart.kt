package com.dpsmpx.dppass.app

/** D-120: подключение маршрута выполняется последним, под блокировкой сессии. */
internal object RootHotspotStart {
    enum class Result { READY, REFUSED, CLEANUP_PENDING }

    fun run(
        session: RootHotspotAdmission.Session,
        prepareGuardedSession: () -> RootHotspotAdmission.Evidence,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): Result = runPrepared(
        { RootHotspotAdmission.refusal(session, prepareGuardedSession()) == null }, attach, shutdown,
    )

    /** Shared rollback contract for sessions whose interface is discovered later. */
    fun runPrepared(
        prepare: () -> Boolean,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): Result {
        val ready = try {
            prepare() && attach()
        } catch (failure: Throwable) {
            try {
                val cleanup = shutdown()
                if (cleanup != RootHotspotShutdown.Result.STOPPED) {
                    failure.addSuppressed(IllegalStateException("ROOT hotspot cleanup unconfirmed: $cleanup"))
                }
            } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
        return when {
            ready -> Result.READY
            shutdown() == RootHotspotShutdown.Result.STOPPED -> Result.REFUSED
            else -> Result.CLEANUP_PENDING
        }
    }
}
