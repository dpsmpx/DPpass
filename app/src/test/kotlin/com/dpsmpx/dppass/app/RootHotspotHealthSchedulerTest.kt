package com.dpsmpx.dppass.app

import java.util.concurrent.RejectedExecutionException
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotHealthSchedulerTest {
    private class Runtime(private val request: RootHotspotLifecycle.Request) : RootHotspotServiceOwner.Runtime {
        var state = RootHotspotLifecycle.State.IDLE
        var healthy = true
        var stopOk = true
        var checks = 0
        var stops = 0
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
        override fun verifyReady() = healthy.also { checks++ }
    }

    private class Task(val delay: Long, val run: () -> Unit) {
        var cancelled = false
    }
    private class Fixture {
        val owner = RootHotspotServiceOwner()
        val tasks = mutableListOf<Task>()
        val results = mutableListOf<RootHotspotServiceOwner.Result>()
        var reject = false
        var reportFailure = false
        lateinit var runtime: Runtime
        val scheduler = RootHotspotHealthScheduler(owner, { delay, run ->
            if (reject) throw RejectedExecutionException()
            val task = Task(delay, run).also(tasks::add)
            RootHotspotHealthScheduler.Cancellation { task.cancelled = true }
        }, 5000) { _, result ->
            results += result
            if (reportFailure) error("report unavailable")
        }
        fun start(): RootHotspotLifecycle.Request {
            assertEquals(RootHotspotServiceOwner.Result.READY,
                owner.start(RootHotspotAdmission.Mode.VPN) { Runtime(it).also { runtime = it } })
            return requireNotNull(owner.snapshot().request)
        }
    }

    @Test fun intervalBoundsAreEnforced() {
        for (interval in listOf(0L, 999L, 60001L)) {
            assertThrows(IllegalArgumentException::class.java) {
                RootHotspotHealthScheduler(RootHotspotServiceOwner(), { _, _ -> error("unused") }, interval) { _, _ -> }
            }
        }
    }

    @Test fun healthyPassSchedulesOneNextCheckAndDuplicateArmDoesNotPostpone() {
        val f = Fixture()
        val request = f.start()
        assertTrue(f.scheduler.arm(request))
        assertTrue(f.scheduler.arm(request))
        assertEquals(1, f.tasks.size)
        assertEquals(5000L, f.tasks.single().delay)
        f.tasks.first().run()
        assertEquals(1, f.runtime.checks)
        assertEquals(2, f.tasks.size)
        assertEquals(listOf(RootHotspotServiceOwner.Result.READY), f.results)
        f.tasks.first().run()
        assertEquals(1, f.runtime.checks)
    }

    @Test fun lostProofStopsAndNeverReschedules() {
        val f = Fixture()
        val request = f.start()
        f.scheduler.arm(request)
        f.runtime.healthy = false
        f.tasks.single().run()
        assertEquals(1, f.runtime.stops)
        assertEquals(1, f.tasks.size)
        assertEquals(listOf(RootHotspotServiceOwner.Result.STOPPED), f.results)
        assertFalse(f.scheduler.arm(request))
    }

    @Test fun failedCleanupRemainsExplicitRetryOnly() {
        val f = Fixture()
        val request = f.start()
        f.scheduler.arm(request)
        f.runtime.healthy = false
        f.runtime.stopOk = false
        f.tasks.single().run()
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, f.owner.snapshot().state)
        assertEquals(1, f.tasks.size)
        f.runtime.stopOk = true
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.scheduler.stop(request))
    }

    @Test fun stopInvalidatesEvenAlreadyQueuedTimer() {
        val f = Fixture()
        val request = f.start()
        f.scheduler.arm(request)
        assertEquals(RootHotspotServiceOwner.Result.STOPPED, f.scheduler.stop(request))
        assertTrue(f.tasks.single().cancelled)
        f.tasks.single().run()
        assertEquals(0, f.runtime.checks)
    }

    @Test fun staleTimerAndStopCannotTouchReplacement() {
        val f = Fixture()
        val first = f.start()
        f.scheduler.arm(first)
        f.owner.stop(first)
        val second = f.start()
        assertTrue(f.scheduler.arm(second))
        assertFalse(f.scheduler.arm(first))
        assertEquals(RootHotspotServiceOwner.Result.STALE, f.scheduler.stop(first))
        f.tasks.first().run()
        assertEquals(0, f.runtime.checks)
        f.tasks.last().run()
        assertEquals(1, f.runtime.checks)
    }

    @Test fun initialScheduleRejectionStopsSession() {
        val f = Fixture()
        val request = f.start()
        f.reject = true
        assertFalse(f.scheduler.arm(request))
        assertEquals(1, f.runtime.stops)
        assertEquals(listOf(RootHotspotServiceOwner.Result.STOPPED), f.results)
    }

    @Test fun repeatScheduleRejectionStopsInsteadOfReportingReady() {
        val f = Fixture()
        val request = f.start()
        f.scheduler.arm(request)
        f.reject = true
        f.tasks.single().run()
        assertEquals(1, f.runtime.checks)
        assertEquals(1, f.runtime.stops)
        assertEquals(listOf(RootHotspotServiceOwner.Result.STOPPED), f.results)
    }

    @Test fun resultObserverFailureDoesNotCancelNextCheck() {
        val f = Fixture()
        f.reportFailure = true
        f.scheduler.arm(f.start())
        f.tasks.first().run()
        f.tasks.last().run()
        assertEquals(2, f.runtime.checks)
        assertEquals(3, f.tasks.size)
    }
}
