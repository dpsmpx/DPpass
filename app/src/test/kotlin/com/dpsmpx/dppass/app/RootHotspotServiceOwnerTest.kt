package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RootHotspotServiceOwnerTest {
    private val mode = RootHotspotAdmission.Mode.VPN
    private class Runtime(private val request: RootHotspotLifecycle.Request) : RootHotspotServiceOwner.Runtime {
        var state = RootHotspotLifecycle.State.IDLE
        var startResult = RootHotspotLifecycle.StartResult.READY
        var stopResult = RootHotspotLifecycle.StopResult.STOPPED
        var beforeStart: () -> Unit = {}
        var beforeStop: () -> Unit = {}
        var stops = 0
        override fun start(): RootHotspotLifecycle.StartResult {
            state = RootHotspotLifecycle.State.STARTING
            beforeStart()
            state = when (startResult) {
                RootHotspotLifecycle.StartResult.READY -> RootHotspotLifecycle.State.READY
                RootHotspotLifecycle.StartResult.REFUSED, RootHotspotLifecycle.StartResult.CANCELLED ->
                    RootHotspotLifecycle.State.IDLE
                else -> RootHotspotLifecycle.State.CLEANUP_PENDING
            }
            return startResult
        }
        override fun stop(): RootHotspotLifecycle.StopResult {
            stops++
            beforeStop()
            state = if (stopResult == RootHotspotLifecycle.StopResult.STOPPED)
                RootHotspotLifecycle.State.IDLE else RootHotspotLifecycle.State.CLEANUP_PENDING
            return stopResult
        }
        override fun snapshot() = RootHotspotLifecycle.Snapshot(state,
            if (state == RootHotspotLifecycle.State.READY)
                RootHotspotAdmission.Session(request.generation, 12, request.mode) else null,
            request = request.takeUnless { state == RootHotspotLifecycle.State.IDLE })
    }

    @Test fun staleCallbacksCannotStopReplacementSession() {
        val service = RootHotspotServiceOwner()
        assertEquals(RootHotspotServiceOwner.Result.READY, service.start(mode, ::Runtime))
        val first = requireNotNull(service.snapshot().request)
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.stop(first))
        assertEquals(RootHotspotServiceOwner.Result.READY, service.start(mode, ::Runtime))
        val second = requireNotNull(service.snapshot().request)
        assertEquals(first.generation + 1, second.generation)
        assertEquals(RootHotspotServiceOwner.Result.STALE, service.stop(first))
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.stop(second))
    }

    @Test fun overlappingStartNeverConstructsAnotherRuntime() {
        val service = RootHotspotServiceOwner()
        assertEquals(RootHotspotServiceOwner.Result.READY, service.start(mode, ::Runtime))
        assertEquals(RootHotspotServiceOwner.Result.BUSY, service.start(mode) { error("duplicate runtime") })
    }

    @Test fun pendingCleanupBlocksNewServiceAndCanBeRetried() {
        val service = RootHotspotServiceOwner()
        lateinit var runtime: Runtime
        assertEquals(RootHotspotServiceOwner.Result.READY, service.start(mode) {
            Runtime(it).also { runtime = it }
        })
        val request = requireNotNull(service.snapshot().request)
        runtime.stopResult = RootHotspotLifecycle.StopResult.CLEANUP_PENDING
        assertEquals(RootHotspotServiceOwner.Result.CLEANUP_PENDING, service.stop(request))
        assertEquals(RootHotspotServiceOwner.Result.BUSY, service.start(mode) { error("must retain owner") })
        runtime.stopResult = RootHotspotLifecycle.StopResult.STOPPED
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.stop(request))
        assertEquals(2, runtime.stops)
    }

    @Test fun stopDuringFactoryPreventsRuntimeStart() {
        val service = RootHotspotServiceOwner()
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.start(mode) { request ->
            assertEquals(RootHotspotServiceOwner.Result.CANCEL_REQUESTED, service.stop(request))
            Runtime(request).apply { beforeStart = { error("cancelled") } }
        })
        assertEquals(RootHotspotServiceOwner.State.IDLE, service.snapshot().state)
    }

    @Test fun stopDuringStartRollsBackBeforeReady() {
        val service = RootHotspotServiceOwner()
        lateinit var runtime: Runtime
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.start(mode) { request ->
            Runtime(request).also {
                runtime = it
                it.beforeStart = {
                    assertEquals(RootHotspotServiceOwner.Result.CANCEL_REQUESTED, service.stop(request))
                }
            }
        })
        assertEquals(1, runtime.stops)
        assertEquals(RootHotspotServiceOwner.State.IDLE, service.snapshot().state)
    }

    @Test fun exceptionalStartAndStopRetainOwnerForRetry() {
        val service = RootHotspotServiceOwner()
        lateinit var runtime: Runtime
        assertThrows(IllegalStateException::class.java) {
            service.start(mode) { request ->
                Runtime(request).also { runtime = it; it.beforeStart = { error("start failed") } }
            }
        }
        val request = requireNotNull(service.snapshot().request)
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, service.snapshot().state)
        runtime.beforeStop = { error("stop failed") }
        assertThrows(IllegalStateException::class.java) { service.stop(request) }
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, service.snapshot().state)
        runtime.beforeStop = {}
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, service.stop(request))
    }
}
