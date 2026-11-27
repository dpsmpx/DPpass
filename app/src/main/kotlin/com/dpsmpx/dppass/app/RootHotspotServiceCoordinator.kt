package com.dpsmpx.dppass.app

import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledThreadPoolExecutor

/**
 * Service worker boundary. One worker for start, stop and health passes;
 * never publish READY until the health timer is armed. UI callbacks receive
 * only the current process snapshot, not configuration or shell output.
 * Constructing this host does not activate or restore a hotspot.
 */
internal class RootHotspotServiceCoordinator(
    private val owner: RootHotspotServiceOwner,
    private val worker: ScheduledExecutorService,
    private val publish: (RootHotspotServiceOwner.Snapshot) -> Unit,
    intervalMillis: Long = 10_000,
) {
    private val monitor = Any()
    private var queuedStart = false
    private val queuedStops = mutableSetOf<RootHotspotLifecycle.Request>()
    private val scheduler = RootHotspotHealthScheduler.onWorker(owner, worker, intervalMillis) { _, _ -> report() }

    fun snapshot(): RootHotspotServiceOwner.Snapshot = owner.snapshot()

    /** Accept one explicit command, never store a factory for restoration. */
    fun start(mode: RootHotspotAdmission.Mode,
              factory: (RootHotspotLifecycle.Request) -> RootHotspotServiceOwner.Runtime): Boolean {
        synchronized(monitor) {
            if (queuedStart || owner.snapshot().state != RootHotspotServiceOwner.State.IDLE) return false
            queuedStart = true
        }
        return try {
            worker.execute {
                try {
                    val result = owner.start(mode, factory)
                    if (result == RootHotspotServiceOwner.Result.READY) {
                        val request = checkNotNull(owner.snapshot().request)
                        // arm() performs fail-closed stop if scheduling fails.
                        scheduler.arm(request)
                    }
                } finally {
                    synchronized(monitor) { queuedStart = false }
                    report()
                }
            }
            true
        } catch (failure: Exception) {
            synchronized(monitor) { queuedStart = false }
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            report()
            false
        }
    }

    /** Exact-generation stop, also used by an unexpected AP callback.
     * Cooperatively cancel an in-flight start or health check immediately.
     * Deduplicate worker commands; never stop a newer owner. */
    fun stop(request: RootHotspotLifecycle.Request): Boolean {
        if (owner.cancelInFlight(request)) return true
        synchronized(monitor) {
            if (owner.snapshot().request != request) return false
            if (!queuedStops.add(request)) return true
        }
        return try {
            worker.execute {
                try {
                    scheduler.stop(request)
                } finally {
                    synchronized(monitor) { queuedStops.remove(request) }
                    report()
                }
            }
            true
        } catch (failure: Exception) {
            synchronized(monitor) { queuedStops.remove(request) }
            if (failure is InterruptedException) Thread.currentThread().interrupt()
            report()
            false
        }
    }

    private fun report() {
        try { publish(owner.snapshot()) } catch (_: Exception) { }
    }

    companion object {
        /** Process-lifetime worker; service destruction must not shut down
         * this executor while an exact owner or timer is retained. */
        fun processWorker(): ScheduledThreadPoolExecutor =
            ScheduledThreadPoolExecutor(1) { task ->
                Thread(task, "dppass-root-hotspot").apply { isDaemon = true }
            }.apply {
                removeOnCancelPolicy = true
                setExecuteExistingDelayedTasksAfterShutdownPolicy(false)
                setContinueExistingPeriodicTasksAfterShutdownPolicy(false)
            }
    }
}
