package com.dpsmpx.dppass.app

/** D-120: подключение маршрута выполняется последним, под блокировкой сессии. */
internal object RootHotspotStart {
    enum class Result { READY, REFUSED, CLEANUP_PENDING }

    fun run(
        session: RootHotspotAdmission.Session,
        prepareGuardedSession: () -> RootHotspotAdmission.Evidence,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): Result {
        val ready = try {
            val evidence = prepareGuardedSession()
            RootHotspotAdmission.refusal(session, evidence) == null && attach()
        } catch (failure: Exception) {
            try {
                shutdown()
            } catch (cleanup: Exception) {
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
