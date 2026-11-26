package com.dpsmpx.dppass.app

/**
 * D-120: owns one experimental hotspot session and its exact cleanup operation.
 * Calls are serialized under the lifecycle monitor; callbacks must be bounded
 * and must not wait for another thread invoking this owner. No Android service
 * is started here. Cross-process ROOT locking remains the caller's obligation.
 */
internal class RootHotspotLifecycle {
    enum class State { IDLE, STARTING, READY, STOPPING, CLEANUP_PENDING }
    enum class StartResult { READY, REFUSED, BUSY, STALE, CLEANUP_PENDING }
    enum class StopResult { STOPPED, STALE, BUSY, CLEANUP_PENDING }
    data class Snapshot(val state: State, val session: RootHotspotAdmission.Session?)

    private var state = State.IDLE
    private var lastGeneration = 0L
    private var session: RootHotspotAdmission.Session? = null
    private var cleanup: (() -> RootHotspotShutdown.Result)? = null

    @Synchronized
    fun snapshot(): Snapshot = Snapshot(state, session)

    @Synchronized
    fun start(
        request: RootHotspotAdmission.Session,
        prepare: () -> RootHotspotAdmission.Evidence,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): StartResult {
        if (state != State.IDLE) return StartResult.BUSY
        if (request.generation <= lastGeneration) return StartResult.STALE
        lastGeneration = request.generation
        session = request
        cleanup = shutdown
        state = State.STARTING
        var cleaned = false
        return try {
            val result = RootHotspotStart.run(request, prepare, attach) {
                shutdown().also { cleaned = it == RootHotspotShutdown.Result.STOPPED }
            }
            when (result) {
                RootHotspotStart.Result.READY -> {
                    state = State.READY
                    StartResult.READY
                }
                RootHotspotStart.Result.REFUSED -> {
                    clear()
                    StartResult.REFUSED
                }
                RootHotspotStart.Result.CLEANUP_PENDING -> {
                    state = State.CLEANUP_PENDING
                    StartResult.CLEANUP_PENDING
                }
            }
        } catch (failure: Throwable) {
            if (cleaned) clear() else state = State.CLEANUP_PENDING
            throw failure
        }
    }

    @Synchronized
    fun stop(request: RootHotspotAdmission.Session): StopResult {
        if (session != request) return StopResult.STALE
        if (state == State.STARTING || state == State.STOPPING) return StopResult.BUSY
        val shutdown = checkNotNull(cleanup)
        state = State.STOPPING
        return try {
            if (shutdown() == RootHotspotShutdown.Result.STOPPED) {
                clear()
                StopResult.STOPPED
            } else {
                state = State.CLEANUP_PENDING
                StopResult.CLEANUP_PENDING
            }
        } catch (failure: Throwable) {
            state = State.CLEANUP_PENDING
            throw failure
        }
    }

    private fun clear() {
        session = null
        cleanup = null
        state = State.IDLE
    }
}
