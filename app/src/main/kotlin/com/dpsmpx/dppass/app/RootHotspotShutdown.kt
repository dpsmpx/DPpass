package com.dpsmpx.dppass.app

/** D-120: порядок остановки под блокировкой владельца одной сессии. */
internal object RootHotspotShutdown {
    enum class Result { STOPPED, GUARD_RETAINED, CLEANUP_PENDING }

    /** Операции должны быть повторяемыми; отсутствие AP нужно подтвердить, а не предположить. */
    fun run(stopEgress: () -> Boolean, closeAndVerifyAccessPoint: () -> Boolean, retireGuards: () -> Boolean): Result {
        val egressStopped: Boolean
        val accessPointStopped: Boolean
        try {
            egressStopped = stopEgress()
        } finally {
            accessPointStopped = closeAndVerifyAccessPoint()
        }
        if (!accessPointStopped) return Result.GUARD_RETAINED
        if (!egressStopped || !retireGuards()) return Result.CLEANUP_PENDING
        return Result.STOPPED
    }
}
