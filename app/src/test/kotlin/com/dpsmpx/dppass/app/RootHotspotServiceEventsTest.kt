package com.dpsmpx.dppass.app

import java.util.concurrent.Executor
import java.util.concurrent.RejectedExecutionException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotServiceEventsTest {
    private val mode = RootHotspotAdmission.Mode.VPN
    private class Runtime(private val request: RootHotspotLifecycle.Request) : RootHotspotServiceOwner.Runtime {
        var current = RootHotspotLifecycle.State.IDLE
        var beforeStart: () -> Unit = {}
        var beforeStop: () -> Unit = {}
        var refused = false
        var failSnapshot = false
        var stops = 0
        override fun start(): RootHotspotLifecycle.StartResult {
            beforeStart()
            current = if (refused) RootHotspotLifecycle.State.IDLE else RootHotspotLifecycle.State.READY
            return if (refused) RootHotspotLifecycle.StartResult.REFUSED else RootHotspotLifecycle.StartResult.READY
        }
        override fun stop(): RootHotspotLifecycle.StopResult {
            stops++
            beforeStop()
            current = RootHotspotLifecycle.State.IDLE
            return RootHotspotLifecycle.StopResult.STOPPED
        }
        override fun snapshot(): RootHotspotLifecycle.Snapshot {
            check(!failSnapshot)
            return RootHotspotLifecycle.Snapshot(current,
                if (current == RootHotspotLifecycle.State.READY)
                    RootHotspotAdmission.Session(request.generation, 12, request.mode) else null)
        }
    }

    @Test fun callbackDuringStartupCancelsWithoutSchedulingRootWork() {
        val owner = RootHotspotServiceOwner()
        val events = RootHotspotServiceEvents(owner, Executor { error("must not schedule") }) { _, _ ->
            error("unexpected failure")
        }
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, owner.start(mode) { request ->
            Runtime(request).apply { beforeStart = { assertTrue(events.platformStopped(request)) } }
        })
        assertEquals(RootHotspotServiceOwner.State.IDLE, owner.snapshot().state)
    }

    @Test fun staleQueuedEventCannotStopReplacement() {
        val owner = RootHotspotServiceOwner()
        val queue = mutableListOf<Runnable>()
        val events = RootHotspotServiceEvents(owner, Executor { queue.add(it) }) { _, _ -> error("unexpected") }
        assertEquals(RootHotspotServiceOwner.Result.READY, owner.start(mode, ::Runtime))
        val first = requireNotNull(owner.snapshot().request)
        assertTrue(events.platformStopped(first))
        assertEquals(1, queue.size)
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, owner.stop(first))
        assertEquals(RootHotspotServiceOwner.Result.READY, owner.start(mode, ::Runtime))
        val second = requireNotNull(owner.snapshot().request)
        queue.single().run()
        assertEquals(second, owner.snapshot().request)
        assertFalse(events.platformStopped(first))
        assertTrue(events.platformStopped(second))
        queue.last().run()
        assertEquals(RootHotspotServiceOwner.State.IDLE, owner.snapshot().state)
    }

    @Test fun rejectedWorkerKeepsOwnerAndReportsFailure() {
        val owner = RootHotspotServiceOwner()
        assertEquals(RootHotspotServiceOwner.Result.READY, owner.start(mode, ::Runtime))
        val request = requireNotNull(owner.snapshot().request)
        val failures = mutableListOf<Exception>()
        val events = RootHotspotServiceEvents(owner, Executor { throw RejectedExecutionException() }) { exact, failure ->
            assertEquals(request, exact)
            failures += failure
        }
        assertFalse(events.platformStopped(request))
        assertEquals(1, failures.size)
        assertEquals(request, owner.snapshot().request)
    }

    @Test fun stopExceptionRetainsOwnerAndReportsFailure() {
        val owner = RootHotspotServiceOwner()
        assertEquals(RootHotspotServiceOwner.Result.READY, owner.start(mode) {
            Runtime(it).apply { beforeStop = { error("stop failed") } }
        })
        val request = requireNotNull(owner.snapshot().request)
        val failures = mutableListOf<Exception>()
        val events = RootHotspotServiceEvents(owner, Executor { it.run() }) { _, failure -> failures += failure }
        assertTrue(events.platformStopped(request))
        assertEquals(1, failures.size)
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, owner.snapshot().state)
    }

    @Test fun refusedRuntimeSnapshotFailureRetainsOwnerForRetry() {
        val owner = RootHotspotServiceOwner()
        lateinit var runtime: Runtime
        assertThrows(IllegalStateException::class.java) {
            owner.start(mode) { request ->
                Runtime(request).also { runtime = it; it.refused = true; it.failSnapshot = true }
            }
        }
        val request = requireNotNull(owner.snapshot().request)
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, owner.snapshot().state)
        runtime.failSnapshot = false
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, owner.stop(request))
    }
}
