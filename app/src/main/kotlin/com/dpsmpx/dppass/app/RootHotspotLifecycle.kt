package com.dpsmpx.dppass.app

/**
 * D-120: owns one experimental hotspot session and its exact cleanup operation.
 * Only state transitions take the private monitor. Resource callbacks run
 * outside it while the reserved operation prevents competing side effects.
 * A stop during startup requests cooperative cancellation. An already admitted
 * callback may finish; the owner rolls it back before publishing READY.
 * Callbacks must be bounded. Cross-process ROOT locking remains the caller's obligation.
 */
internal class RootHotspotLifecycle {
    enum class State { IDLE, STARTING, READY, STOPPING, CLEANUP_PENDING }
    enum class StartResult { READY, REFUSED, CANCELLED, BUSY, STALE, CLEANUP_PENDING }
    enum class StopResult { STOPPED, CANCEL_REQUESTED, STALE, BUSY, CLEANUP_PENDING }
    data class Request(val generation: Long, val mode: RootHotspotAdmission.Mode) {
        init { require(generation > 0) }
        fun matches(session: RootHotspotAdmission.Session): Boolean =
            generation == session.generation && mode == session.mode
    }

    data class Snapshot(
        val state: State,
        val session: RootHotspotAdmission.Session?,
        val cancellationRequested: Boolean = false,
        val request: Request? = session?.let { Request(it.generation, it.mode) },
    )

    private class Owner(
        val request: Request,
        var session: RootHotspotAdmission.Session?,
        val shutdown: () -> RootHotspotShutdown.Result,
    ) {
        // Access only under monitor.
        var cancellationRequested = false
    }

    private val monitor = Any()
    private var state = State.IDLE
    private var lastGeneration = 0L
    private var owner: Owner? = null

    fun snapshot(): Snapshot = synchronized(monitor) {
        Snapshot(state, owner?.session, owner?.cancellationRequested == true, owner?.request)
    }

    fun start(
        request: RootHotspotAdmission.Session,
        prepare: () -> RootHotspotAdmission.Evidence,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): StartResult = startOperation(
        Request(request.generation, request.mode), request,
        { RootHotspotAdmission.refusal(request, prepare()) == null }, attach, shutdown,
    )

    /** Reserve the in-process lifecycle before AP dispatch; bind exactly once
     * after discovery. The callback returns false after cancellation. */
    fun startPending(
        request: Request,
        prepare: ((RootHotspotAdmission.Session) -> Boolean) -> Boolean,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): StartResult = startOperation(request, null, prepare, attach, shutdown)

    private fun startOperation(
        request: Request,
        initial: RootHotspotAdmission.Session?,
        prepare: ((RootHotspotAdmission.Session) -> Boolean) -> Boolean,
        attach: () -> Boolean,
        shutdown: () -> RootHotspotShutdown.Result,
    ): StartResult {
        val operation = synchronized(monitor) {
            if (state != State.IDLE) return StartResult.BUSY
            if (request.generation <= lastGeneration) return StartResult.STALE
            check(owner == null)
            lastGeneration = request.generation
            Owner(request, initial, shutdown).also {
                owner = it
                state = State.STARTING
            }
        }

        var cleaned = false
        val result = try {
            RootHotspotStart.runPrepared({
                prepare { discovered ->
                    synchronized(monitor) {
                        check(owner === operation && state == State.STARTING)
                        require(operation.request.matches(discovered))
                        check(operation.session == null) { "ROOT hotspot already bound" }
                        operation.session = discovered
                        !operation.cancellationRequested
                    }
                }
            }, {
                // Admission point: cancellation before this check prevents attach.
                // Cancellation after it is handled by rollback before READY.
                val admitted = synchronized(monitor) {
                    check(owner === operation && state == State.STARTING)
                    operation.session != null && !operation.cancellationRequested
                }
                admitted && attach()
            }) {
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
                val published = synchronized(monitor) {
                    check(owner === operation && state == State.STARTING)
                    if (operation.cancellationRequested) {
                        state = State.STOPPING
                        false
                    } else {
                        state = State.READY
                        true
                    }
                }
                if (published) StartResult.READY
                else if (completeStop(operation) == StopResult.STOPPED) StartResult.CANCELLED
                else StartResult.CLEANUP_PENDING
            }
            RootHotspotStart.Result.REFUSED -> {
                val cancelled = synchronized(monitor) {
                    check(owner === operation && state == State.STOPPING)
                    operation.cancellationRequested
                }
                finish(operation, State.IDLE)
                if (cancelled) StartResult.CANCELLED else StartResult.REFUSED
            }
            RootHotspotStart.Result.CLEANUP_PENDING -> {
                finish(operation, State.CLEANUP_PENDING)
                StartResult.CLEANUP_PENDING
            }
        }
    }

    fun stop(request: RootHotspotAdmission.Session): StopResult =
        stopMatching { it.session == request }

    fun stop(request: Request): StopResult = stopMatching { it.request == request }

    private fun stopMatching(matches: (Owner) -> Boolean): StopResult {
        val operation = synchronized(monitor) {
            val current = owner
            if (current == null || !matches(current)) return StopResult.STALE
            if (state == State.STARTING) {
                current.cancellationRequested = true
                return StopResult.CANCEL_REQUESTED
            }
            if (state == State.STOPPING) return StopResult.BUSY
            check(state == State.READY || state == State.CLEANUP_PENDING)
            state = State.STOPPING
            current
        }
        return completeStop(operation)
    }

    private fun completeStop(operation: Owner): StopResult {
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
        check(next == State.IDLE || next == State.CLEANUP_PENDING)
        if (next == State.IDLE) owner = null
        state = next
    }
}
