package com.dpsmpx.dppass.app

/** Retains exact taken and discarded AP resources until verified retirement. */
internal class RootHotspotReservationOwner<R : Any>(private val release: (R) -> Unit) {
    val pending = RootHotspotReservation(release)
    // Accessed only by the exclusive lifecycle operation. If release
    // throws, retain this exact identity for the next shutdown attempt.
    private var taken: R? = null

    fun take(timeoutMillis: Long): R = pending.take(timeoutMillis).also { taken = it }
    fun resource(): R = checkNotNull(taken)

    fun closeAndVerify(verifyStopped: () -> Boolean): Boolean {
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

}
