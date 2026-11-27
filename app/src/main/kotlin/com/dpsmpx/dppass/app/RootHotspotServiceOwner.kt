package com.dpsmpx.dppass.app

/**
 * Process-local service session boundary. A service must keep this owner
 * across its destruction/recreation until cleanup is positively confirmed.
 * The factory and runtime are internal, bounded worker operations. The
 * Android callback thread must only schedule a stop on a worker.
 * No Android service registration or production activation here.
 */
internal class RootHotspotServiceOwner {
    interface Runtime {
        fun start(): RootHotspotLifecycle.StartResult
        fun stop(): RootHotspotLifecycle.StopResult
        fun snapshot(): RootHotspotLifecycle.Snapshot
    }

    enum class State { IDLE, STARTING, READY, STOPPING, CLEANUP_PENDING }
    enum class Result { READY, REFUSED, BUSY, STALE, CANCEL_REQUESTED, STOPPED, CLEANUP_PENDING }
    data class Snapshot(val state: State, val request: RootHotspotLifecycle.Request?)
    private class Owner(val request: RootHotspotLifecycle.Request) {
        var runtime: Runtime? = null
        var cancel = false
    }
    private val monitor = Any()
    private var owner: Owner? = null
    private var state = State.IDLE
    private var generation = 0L

    fun snapshot(): Snapshot = synchronized(monitor) { Snapshot(state, owner?.request) }

    /** Factory must not acquire resources. The runtime start owns all side
     * effects and must publish cleanup pending if rollback is uncertain. */
    fun start(mode: RootHotspotAdmission.Mode,
              factory: (RootHotspotLifecycle.Request) -> Runtime): Result {
        val operation = synchronized(monitor) {
            if (owner != null) return Result.BUSY
            check(generation < Long.MAX_VALUE)
            Owner(RootHotspotLifecycle.Request(++generation, mode)).also {
                owner = it
                state = State.STARTING
            }
        }
        val runtime = try {
            factory(operation.request)
        } catch (failure: Throwable) {
            finish(operation, State.IDLE)
            throw failure
        }
        val cancelled = synchronized(monitor) {
            check(owner === operation && state == State.STARTING)
            operation.runtime = runtime
            operation.cancel
        }
        if (cancelled) {
            finish(operation, State.IDLE)
            return Result.STOPPED
        }
        val result = try {
            val started = runtime.start()
            if (started == RootHotspotLifecycle.StartResult.READY) {
                val actual = runtime.snapshot()
                check(actual.state == RootHotspotLifecycle.State.READY &&
                    actual.request == operation.request && actual.session?.let(operation.request::matches) == true) {
                    "ROOT hotspot runtime reported READY without matching bound session"
                }
            }
            started
        } catch (failure: Throwable) {
            // Retain even an apparently idle runtime: a thrown start does not
            // establish absence of external resources.
            finish(operation, State.CLEANUP_PENDING)
            throw failure
        }
        return when (result) {
            RootHotspotLifecycle.StartResult.READY -> {
                val published = synchronized(monitor) {
                    check(owner === operation && state == State.STARTING)
                    state = if (operation.cancel) State.STOPPING else State.READY
                    !operation.cancel
                }
                if (published) Result.READY else completeStop(operation)
            }
            RootHotspotLifecycle.StartResult.REFUSED, RootHotspotLifecycle.StartResult.CANCELLED -> {
                if (runtime.snapshot().state == RootHotspotLifecycle.State.IDLE) {
                    finish(operation, State.IDLE)
                    if (result == RootHotspotLifecycle.StartResult.CANCELLED) Result.STOPPED else Result.REFUSED
                } else {
                    finish(operation, State.CLEANUP_PENDING)
                    Result.CLEANUP_PENDING
                }
            }
            else -> {
                finish(operation, State.CLEANUP_PENDING)
                Result.CLEANUP_PENDING
            }
        }
    }

    /** Stop is exact-generation. An event from an old AP cannot stop a new
     * session. During startup it records cancellation; the startup worker
     * performs rollback before the service publishes READY. */
    fun stop(request: RootHotspotLifecycle.Request): Result {
        val operation = synchronized(monitor) {
            val current = owner ?: return Result.STALE
            if (current.request != request) return Result.STALE
            when (state) {
                State.STARTING -> { current.cancel = true; return Result.CANCEL_REQUESTED }
                State.STOPPING -> return Result.BUSY
                State.READY, State.CLEANUP_PENDING -> state = State.STOPPING
                State.IDLE -> error("owner without state")
            }
            current
        }
        return completeStop(operation)
    }

    private fun completeStop(operation: Owner): Result {
        val runtime = checkNotNull(operation.runtime)
        val stopped = try {
            runtime.stop() == RootHotspotLifecycle.StopResult.STOPPED &&
                runtime.snapshot().state == RootHotspotLifecycle.State.IDLE
        } catch (failure: Throwable) {
            finish(operation, State.CLEANUP_PENDING)
            throw failure
        }
        finish(operation, if (stopped) State.IDLE else State.CLEANUP_PENDING)
        return if (stopped) Result.STOPPED else Result.CLEANUP_PENDING
    }

    private fun finish(operation: Owner, next: State) = synchronized(monitor) {
        check(owner === operation)
        if (next == State.IDLE) owner = null
        state = next
    }
}
