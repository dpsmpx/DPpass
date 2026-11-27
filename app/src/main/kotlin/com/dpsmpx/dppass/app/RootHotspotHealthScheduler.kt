package com.dpsmpx.dppass.app

import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit

/**
 * Fixed-delay, exact-session health scheduling. Confined to the service's
 * serial worker, including arm/stop and deferred timer callbacks. No timer
 * may run inline from schedule(). Never restarts a stopped session.
 *
 * If scheduling fails, stop on this worker rather than leave an unmonitored
 * READY session. The observer receives only typed status, not raw errors.
 * Polling is not continuous isolation enforcement.
 */
internal class RootHotspotHealthScheduler(
    private val owner: RootHotspotServiceOwner,
    private val schedule: (Long, () -> Unit) -> Cancellation,
    private val intervalMillis: Long = 10_000,
    private val onResult: (RootHotspotLifecycle.Request, RootHotspotServiceOwner.Result) -> Unit,
) {
    fun interface Cancellation { fun cancel() }
    private class Ticket(val request: RootHotspotLifecycle.Request) {
        var cancellation: Cancellation? = null
    }
    private var pending: Ticket? = null

    init { require(intervalMillis in 1_000..60_000) }

    private fun ready(request: RootHotspotLifecycle.Request): Boolean =
        owner.snapshot() == RootHotspotServiceOwner.Snapshot(RootHotspotServiceOwner.State.READY, request)

    /** Call after successful startup on the worker. Duplicate arm does not
     * extend the deadline. Refuse stale or non-ready requests. */
    fun arm(request: RootHotspotLifecycle.Request): Boolean {
        if (!ready(request)) return false
        if (pending?.request == request) return true
        cancelPending()
        return enqueue(request)
    }

    /** Explicit stop; cancellation is not proof of resource retirement. */
    fun stop(request: RootHotspotLifecycle.Request): RootHotspotServiceOwner.Result {
        if (pending?.request == request) cancelPending()
        return owner.stop(request).also { report(request, it) }
    }

    private fun enqueue(request: RootHotspotLifecycle.Request): Boolean {
        if (!ready(request)) return false
        val ticket = Ticket(request)
        pending = ticket
        try {
            ticket.cancellation = schedule(intervalMillis) { tick(ticket) }
            return true
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            if (pending === ticket) pending = null
            failClosed(request)
            return false
        }
    }

    private fun tick(ticket: Ticket) {
        if (pending !== ticket) return
        pending = null
        val request = ticket.request
        if (!ready(request)) return
        val result = try {
            owner.checkReady(request)
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            // checkReady retains cleanup ownership on shutdown failure.
            report(request, RootHotspotServiceOwner.Result.CLEANUP_PENDING)
            return
        }
        if (result == RootHotspotServiceOwner.Result.READY) {
            if (enqueue(request)) report(request, result)
        } else {
            if (result == RootHotspotServiceOwner.Result.BUSY && ready(request)) failClosed(request)
            else report(request, result)
        }
    }

    private fun failClosed(request: RootHotspotLifecycle.Request) {
        val result = try {
            owner.stop(request)
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            RootHotspotServiceOwner.Result.CLEANUP_PENDING
        }
        report(request, result)
    }

    private fun cancelPending() {
        val ticket = pending
        pending = null // invalidate first even if cancellation fails
        try {
            ticket?.cancellation?.cancel()
        } catch (failure: Exception) {
            if (failure is InterruptedException) Thread.currentThread().interrupt()
        }
    }

    private fun report(request: RootHotspotLifecycle.Request, result: RootHotspotServiceOwner.Result) {
        // A UI reporting failure must not break the next scheduled check.
        try { onResult(request, result) } catch (_: Exception) { }
    }

    companion object {
        /** Executor must be single-threaded and owned by the future service.
         * Cancellation never interrupts in-flight native/ROOT operations. */
        fun onWorker(owner: RootHotspotServiceOwner, worker: ScheduledExecutorService,
                     intervalMillis: Long = 10_000,
                     onResult: (RootHotspotLifecycle.Request, RootHotspotServiceOwner.Result) -> Unit) =
            RootHotspotHealthScheduler(owner, { delay, task ->
                val future = worker.schedule(Runnable { task() }, delay, TimeUnit.MILLISECONDS)
                Cancellation { future.cancel(false) }
            }, intervalMillis, onResult)
    }
}
