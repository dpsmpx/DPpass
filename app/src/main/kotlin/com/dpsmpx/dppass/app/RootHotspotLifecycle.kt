package com.dpsmpx.dppass.app

/**
 * D-120: owns one experimental hotspot session and its exact cleanup operation.
 * Only state transitions take the private monitor. Resource callbacks run
 * outside it while the reserved operation prevents competing side effects.
 * A concurrent stop during startup/rollback returns BUSY, not cancellation;
 * the caller must retry after the transition completes. Callbacks must be
 * bounded. Cross-process ROOT locking remains the caller's obligation.
 */
internal class RootHotspotLifecycle {
    enum class State { IDLE, STARTING, READY, STOPPING, CLEANUP_PENDING }
    enum class StartResult { READY, REFUSED, BUSY, STALE, CLEANUP_PENDING }
    enum class StopResult { STOPPED, STALE, BUSY, CLEANUP_PENDING }
    data class Snapshot(val state: State, val session: RootHotspotAdmission.Session?)

    private class Owner(
        val session: RootHotspotAdmission.Session,
        val shutdown: () -> RootHotspotShutdown.Result,
    )

    private val monitor = Any()
    private var state = State.IDLE
    private var lastGeneration = 0L
    private var owner: Owner? = null

    fun snapshot(): Snapshot = synchronized(monitor) { Snapshot(state, owner?.session) }

    fun start(
        request: RootHotspotAdmission.Session,
        prepare: () -> RootHotspotAdmission.Evidence,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): StartResult {
        val operation = synchronized(monitor) {
            if (state != State.IDLE) return StartResult.BUSY
            if (request.generation <= lastGeneration) return StartResult.STALE
            check(owner == null)
            lastGeneration = request.generation
            Owner(request, shutdown).also {
                owner = it
                state = State.STARTING
            }
        }

        var cleaned = false
        val result = try {
            RootHotspotStart.run(request, prepare, attach) {
                synchronized(monitor) {
                    check(owner === operation && state == State.STARTING)
                    state = State.STOPPING
                }
                operation.shutdown().also { cleaned = it == RootHotspotShutdown.Result.STOPPED }
            }
        } catch (failure: Throwable) {
            finish(operation, if (cleaned) State.IDLE else State.CLEANUP_PENDING)
            throw failure
        }
        return when (result) {
            RootHotspotStart.Result.READY -> {
                finish(operation, State.READY)
                StartResult.READY
            }
            RootHotspotStart.Result.REFUSED -> {
                finish(operation, State.IDLE)
                StartResult.REFUSED
            }
            RootHotspotStart.Result.CLEANUP_PENDING -> {
                finish(operation, State.CLEANUP_PENDING)
                StartResult.CLEANUP_PENDING
            }
        }
    }

    fun stop(request: RootHotspotAdmission.Session): StopResult {
        val operation = synchronized(monitor) {
            val current = owner
            if (current == null || current.session != request) return StopResult.STALE
            if (state == State.STARTING || state == State.STOPPING) return StopResult.BUSY
            check(state == State.READY || state == State.CLEANUP_PENDING)
            state = State.STOPPING
            current
        }
        val stopped = try {
            operation.shutdown() == RootHotspotShutdown.Result.STOPPED
        } catch (failure: Throwable) {
            finish(operation, State.CLEANUP_PENDING)
            throw failure
        }
        finish(operation, if (stopped) State.IDLE else State.CLEANUP_PENDING)
        return if (stopped) StopResult.STOPPED else StopResult.CLEANUP_PENDING
    }

    private fun finish(operation: Owner, next: State) = synchronized(monitor) {
        check(owner === operation)
        check(state == State.STARTING || state == State.STOPPING)
        check(next == State.IDLE || next == State.READY || next == State.CLEANUP_PENDING)
        if (next == State.IDLE) owner = null
        state = next
    }
}
