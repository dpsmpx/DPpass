package com.dpsmpx.dppass.app

/** D-120: порядок остановки под блокировкой владельца одной сессии. */
internal object RootHotspotShutdown {
    enum class Result { STOPPED, GUARD_RETAINED, CLEANUP_PENDING }

    /** Операции должны быть повторяемыми; отсутствие AP нужно подтвердить, а не предположить. */
    fun run(stopEgress: () -> Boolean, closeAndVerifyAccessPoint: () -> Boolean, retireGuards: () -> Boolean): Result {
        val egressStopped = try {
            stopEgress()
        } catch (failure: Throwable) {
            // Even a failed or interrupted egress stop must attempt AP closure.
            // A second failure must not replace the original cause.
            try {
                if (!closeAndVerifyAccessPoint()) {
                    failure.addSuppressed(IllegalStateException("ROOT hotspot AP shutdown unconfirmed"))
                }
            } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
        val accessPointStopped = closeAndVerifyAccessPoint()
        if (!accessPointStopped) return Result.GUARD_RETAINED
        if (!egressStopped || !retireGuards()) return Result.CLEANUP_PENDING
        return Result.STOPPED
    }
}
