package com.dpsmpx.dppass.app

import java.util.IdentityHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * One asynchronous AP request. A successful take transfers ownership once.
 * Discarded resources remain tracked by identity until this request is retired.
 * Callback release failures are retained for an explicit close retry, not
 * thrown into the Android callback thread. A successful release or terminal
 * callback is NOT independent proof that the system AP has disappeared.
 */
internal class RootHotspotReservation<R : Any>(private val release: (R) -> Unit) : AutoCloseable {
    private enum class State { WAITING, READY, TAKEN, ABANDONED, FAILED }
    private enum class ReleaseState { IN_FLIGHT, RETRY, RELEASED }
    private class Discard(var state: ReleaseState, var failure: Throwable? = null)

    data class CleanupStatus(val retry: Int, val inFlight: Int) {
        val unresolved: Boolean get() = retry != 0 || inFlight != 0
    }

    private val monitor = Any()
    private val changed = CountDownLatch(1)
    private val discarded = IdentityHashMap<R, Discard>()
    private var state = State.WAITING
    private var accepted: R? = null
    private var failure: Throwable? = null

    fun cleanupStatus(): CleanupStatus = synchronized(monitor) {
        CleanupStatus(
            discarded.values.count { it.state == ReleaseState.RETRY },
            discarded.values.count { it.state == ReleaseState.IN_FLIGHT },
        )
    }

    fun started(reservation: R) {
        val discard = synchronized(monitor) {
            if (accepted === reservation || discarded.containsKey(reservation)) return
            if (state == State.WAITING) {
                accepted = reservation
                state = State.READY
                changed.countDown()
                false
            } else {
                discarded[reservation] = Discard(ReleaseState.IN_FLIGHT)
                true
            }
        }
        if (discard) releaseOne(reservation)
    }

    fun failed(cause: Throwable) {
        val discard = synchronized(monitor) {
            if (state != State.WAITING && state != State.READY) return
            val pending = if (state == State.READY) accepted else null
            if (pending != null) discarded[pending] = Discard(ReleaseState.IN_FLIGHT)
            failure = cause
            state = State.FAILED
            changed.countDown()
            pending
        }
        if (discard != null) releaseOne(discard)
    }

    /**
     * Wait off the callback thread. Timeout/interruption abandons the request
     * before returning; a concurrently delivered but unclaimed AP is released.
     */
    fun take(timeoutMillis: Long): R {
        require(timeoutMillis > 0)
        try {
            if (!changed.await(timeoutMillis, TimeUnit.MILLISECONDS)) {
                throw TimeoutException("ROOT hotspot reservation timeout")
            }
        } catch (cause: Throwable) {
            try {
                close()
            } catch (cleanup: Throwable) {
                if (cleanup !== cause) cause.addSuppressed(cleanup)
            } finally {
                if (cause is InterruptedException) Thread.currentThread().interrupt()
            }
            throw cause
        }
        return synchronized(monitor) {
            when (state) {
                State.READY -> {
                    state = State.TAKEN
                    checkNotNull(accepted)
                }
                State.FAILED -> throw checkNotNull(failure)
                State.ABANDONED -> error("ROOT hotspot reservation abandoned")
                State.TAKEN -> error("ROOT hotspot reservation already taken")
                State.WAITING -> error("ROOT hotspot reservation not ready")
            }
        }
    }

    /**
     * One bounded pass over known retryable resources. Never invokes a
     * concurrent release for the same identity or reclaims a taken resource.
     * In-flight cleanup is not reported as successful; callers may retry.
     * Future callbacks can still arrive after this method returns.
     */
    override fun close() {
        val work = synchronized(monitor) {
            if (state == State.WAITING || state == State.READY) {
                if (state == State.READY) {
                    discarded[checkNotNull(accepted)] = Discard(ReleaseState.RETRY)
                }
                state = State.ABANDONED
                changed.countDown()
            }
            discarded.entries.filter { it.value.state == ReleaseState.RETRY }.map {
                it.value.state = ReleaseState.IN_FLIGHT
                it.key
            }
        }
        for (resource in work) releaseOne(resource)
        val problem = synchronized(monitor) {
            val unresolved = discarded.values.filter { it.state != ReleaseState.RELEASED }
            if (unresolved.isEmpty()) null else IllegalStateException("ROOT hotspot reservation cleanup unconfirmed").also { error ->
                unresolved.mapNotNull { it.failure }.forEach { if (it !== error) error.addSuppressed(it) }
            }
        }
        if (problem != null) throw problem
    }

    private fun releaseOne(resource: R) {
        val problem = try {
            release(resource)
            null
        } catch (cause: Throwable) {
            cause
        }
        synchronized(monitor) {
            val record = checkNotNull(discarded[resource])
            check(record.state == ReleaseState.IN_FLIGHT)
            record.failure = problem
            record.state = if (problem == null) ReleaseState.RELEASED else ReleaseState.RETRY
        }
        if (problem is InterruptedException) Thread.currentThread().interrupt()
    }
}
