package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotServiceHealthTest {
    private val mode = RootHotspotAdmission.Mode.VPN
    private class Runtime(private val request: RootHotspotLifecycle.Request) : RootHotspotServiceOwner.Runtime {
        var state = RootHotspotLifecycle.State.IDLE
        var healthy = true
        var stopOk = true
        var checks = 0
        var stops = 0
        var duringCheck: () -> Unit = {}
        override fun start(): RootHotspotLifecycle.StartResult {
            state = RootHotspotLifecycle.State.READY
            return RootHotspotLifecycle.StartResult.READY
        }
        override fun stop(): RootHotspotLifecycle.StopResult {
            stops++
            state = if (stopOk) RootHotspotLifecycle.State.IDLE else RootHotspotLifecycle.State.CLEANUP_PENDING
            return if (stopOk) RootHotspotLifecycle.StopResult.STOPPED else RootHotspotLifecycle.StopResult.CLEANUP_PENDING
        }
        override fun snapshot() = RootHotspotLifecycle.Snapshot(state,
            if (state == RootHotspotLifecycle.State.READY) RootHotspotAdmission.Session(request.generation, 12, request.mode) else null)
        override fun verifyReady(): Boolean {
            checks++
            duringCheck()
            return healthy
        }
    }

    private inner class Fixture {
        val owner = RootHotspotServiceOwner()
        lateinit var runtime: Runtime
        val request: RootHotspotLifecycle.Request
        init {
            assertEquals(RootHotspotServiceOwner.Result.READY, owner.start(mode) {
                Runtime(it).also { runtime = it }
            })
            request = requireNotNull(owner.snapshot().request)
        }
        fun check() = owner.checkReady(request)
    }

    @Test fun healthyPassDoesNotMutateResources() {
        val f = Fixture()
        assertEquals(RootHotspotServiceOwner.Result.READY, f.check())
        assertEquals(1, f.runtime.checks)
        assertEquals(0, f.runtime.stops)
    }

    @Test fun staleRequestNeverChecksOrStopsCurrentSession() {
        val f = Fixture()
        assertEquals(RootHotspotServiceOwner.Result.STALE, f.owner.checkReady(f.request.copy(generation = 10)))
        assertEquals(0, f.runtime.checks)
        assertEquals(0, f.runtime.stops)
    }

    @Test fun lossOfProofStopsExactSession() {
        val f = Fixture()
        f.runtime.healthy = false
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.check())
        assertEquals(1, f.runtime.stops)
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.owner.snapshot().state)
    }

    @Test fun stopDuringCheckWaitsForExclusiveWorkerAndSuppressesReady() {
        val f = Fixture()
        f.runtime.duringCheck = {
            assertEquals(RootHotspotServiceOwner.Result.BUSY, f.check())
            assertEquals(RootHotspotServiceOwner.Result.CANCEL_REQUESTED, f.owner.stop(f.request))
            assertEquals(0, f.runtime.stops)
        }
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.check())
        assertEquals(1, f.runtime.stops)
    }

    @Test fun checkExceptionAndFailedShutdownRetainOwner() {
        val f = Fixture()
        f.runtime.duringCheck = { error("proof failed") }
        f.runtime.stopOk = false
        assertEquals(RootHotspotServiceOwner.Result.CLEANUP_PENDING, f.check())
        assertEquals(f.request, f.owner.snapshot().request)
        assertEquals(RootHotspotServiceOwner.Result.BUSY, f.check())
        f.runtime.stopOk = true
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.owner.stop(f.request))
    }

    @Test fun changedSnapshotTriggersShutdownEvenWithPositiveProof() {
        val f = Fixture()
        f.runtime.duringCheck = { f.runtime.state = RootHotspotLifecycle.State.CLEANUP_PENDING }
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.check())
        assertTrue(f.runtime.stops == 1)
    }
}
