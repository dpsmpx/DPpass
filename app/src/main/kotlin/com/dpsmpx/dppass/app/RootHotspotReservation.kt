package com.dpsmpx.dppass.app

import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

/**
 * One asynchronous AP request. A successful take transfers ownership once;
 * abandonment/failure closes an unclaimed reservation, including late arrivals.
 * A terminal callback is not proof that the system interface has disappeared.
 * Release callbacks run outside the monitor and failures remain visible.
 */
internal class RootHotspotReservation<R : Any>(private val release: (R) -> Unit) : AutoCloseable {
    private enum class State { WAITING, READY, TAKEN, ABANDONED, FAILED }

    private val monitor = Any()
    private val changed = CountDownLatch(1)
    private var state = State.WAITING
    private var accepted: R? = null
    private var failure: Throwable? = null

    fun started(reservation: R) {
        val discard = synchronized(monitor) {
            if (accepted === reservation) return
            if (state == State.WAITING) {
                accepted = reservation
                state = State.READY
                changed.countDown()
                false
            } else true
        }
        if (discard) release(reservation)
    }

    fun failed(cause: Throwable) {
        val discard = synchronized(monitor) {
            if (state != State.WAITING && state != State.READY) return
            val pending = if (state == State.READY) accepted else null
            failure = cause
            state = State.FAILED
            changed.countDown()
            pending
        }
        if (discard != null) release(discard)
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

    override fun close() {
        val discard = synchronized(monitor) {
            if (state != State.WAITING && state != State.READY) return
            val pending = if (state == State.READY) accepted else null
            state = State.ABANDONED
            changed.countDown()
            pending
        }
        if (discard != null) release(discard)
    }
}
