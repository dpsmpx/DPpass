package com.dpsmpx.dppass.app

import java.util.concurrent.Executor

/**
 * Process-wide owner and callback bridge for a future Android Service.
 * Start and explicit stop run on service workers. Unexpected AP stop
 * signals cancellation synchronously during startup, otherwise schedules
 * an exact-generation cleanup. An executor rejection is reported to the
 * caller; it never clears the retained owner. No automatic activation.
 */
internal class RootHotspotServiceEvents(
    private val owner: RootHotspotServiceOwner,
    private val worker: Executor,
    private val onFailure: (RootHotspotLifecycle.Request, Exception) -> Unit,
) {
    fun platformStopped(request: RootHotspotLifecycle.Request): Boolean {
        if (owner.cancelStarting(request)) return true
        if (owner.snapshot().request != request) return false
        return try {
            worker.execute {
                try {
                    owner.stop(request)
                } catch (failure: Exception) {
                    onFailure(request, failure)
                }
            }
            true
        } catch (failure: Exception) {
            onFailure(request, failure)
            false
        }
    }
}

/** One owner for service recreation in the same app process. Construction
 * does not perform ROOT commands or acquire resources. */
internal val processRootHotspotServiceOwner = RootHotspotServiceOwner()
