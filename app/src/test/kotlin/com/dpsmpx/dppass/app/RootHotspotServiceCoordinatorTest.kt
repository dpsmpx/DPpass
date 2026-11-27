package com.dpsmpx.dppass.app

import java.util.concurrent.AbstractExecutorService
import java.util.concurrent.Callable
import java.util.concurrent.Delayed
import java.util.concurrent.RejectedExecutionException
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.TimeUnit
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotServiceCoordinatorTest {
    private class Timer(val task: Runnable) : ScheduledFuture<Unit> {
        private var cancelled = false
        override fun cancel(mayInterruptIfRunning: Boolean): Boolean {
            check(!mayInterruptIfRunning)
            cancelled = true
            return true
        }
        override fun isCancelled() = cancelled
        override fun isDone() = cancelled
        override fun get(): Unit = error("not used")
        override fun get(timeout: Long, unit: TimeUnit): Unit = error("not used")
        override fun getDelay(unit: TimeUnit): Long = 0
        override fun compareTo(other: Delayed): Int = 0
    }

    private class Worker : AbstractExecutorService(), ScheduledExecutorService {
        val commands = mutableListOf<Runnable>()
        val timers = mutableListOf<Timer>()
        var rejectCommands = false
        var rejectTimers = false
        override fun execute(command: Runnable) {
            if (rejectCommands) throw RejectedExecutionException()
            commands.add(command)
        }
        override fun schedule(command: Runnable, delay: Long, unit: TimeUnit): ScheduledFuture<*> {
            if (rejectTimers) throw RejectedExecutionException()
            return Timer(command).also { timers.add(it) }
        }
        override fun <V> schedule(callable: Callable<V>, delay: Long, unit: TimeUnit): ScheduledFuture<V> = error("unused")
        override fun scheduleAtFixedRate(command: Runnable, initialDelay: Long, period: Long, unit: TimeUnit): ScheduledFuture<*> = error("unused")
        override fun scheduleWithFixedDelay(command: Runnable, initialDelay: Long, delay: Long, unit: TimeUnit): ScheduledFuture<*> = error("unused")
        override fun shutdown() = Unit
        override fun shutdownNow(): MutableList<Runnable> = mutableListOf()
        override fun isShutdown() = false
        override fun isTerminated() = false
        override fun awaitTermination(timeout: Long, unit: TimeUnit) = false
        fun next() = commands.removeAt(0).run()
    }

    private class Runtime(private val request: RootHotspotLifecycle.Request) : RootHotspotServiceOwner.Runtime {
        var state = RootHotspotLifecycle.State.IDLE
        var healthy = true
        var stopOk = true
        var starts = 0
        var stops = 0
        var duringStart: () -> Unit = {}
        override fun start(): RootHotspotLifecycle.StartResult {
            starts++
            duringStart()
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
        override fun verifyReady() = healthy
    }

    private class Fixture {
        val owner = RootHotspotServiceOwner()
        val worker = Worker()
        val statuses = mutableListOf<RootHotspotServiceOwner.Snapshot>()
        lateinit var runtime: Runtime
        val host = RootHotspotServiceCoordinator(owner, worker, { statuses.add(it) })
        fun start() = host.start(RootHotspotAdmission.Mode.VPN) { Runtime(it).also { runtime = it } }
        fun request() = checkNotNull(host.snapshot().request)
    }

    @Test fun explicitStartIsQueuedOnceAndArmsHealthBeforeReadyReport() {
        val f = Fixture()
        assertTrue(f.start())
        assertFalse(f.start())
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.host.snapshot().state)
        f.worker.next()
        assertEquals(1, f.runtime.starts)
        assertEquals(1, f.worker.timers.size)
        assertEquals(RootHotspotServiceOwner.State.READY, f.statuses.last().state)
        assertFalse(f.start())
    }

    @Test fun schedulerFailureNeverPublishesReady() {
        val f = Fixture()
        f.worker.rejectTimers = true
        assertTrue(f.start())
        f.worker.next()
        assertEquals(1, f.runtime.stops)
        assertTrue(f.statuses.none { it.state == RootHotspotServiceOwner.State.READY })
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.host.snapshot().state)
    }

    @Test fun rejectedStartLeavesNoReservationAndCanBeRetried() {
        val f = Fixture()
        f.worker.rejectCommands = true
        assertFalse(f.start())
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.host.snapshot().state)
        f.worker.rejectCommands = false
        assertTrue(f.start())
        f.worker.next()
        assertEquals(1, f.runtime.starts)
    }

    @Test fun duplicateStopQueuesOneCommandAndCancelsTimer() {
        val f = Fixture()
        f.start()
        f.worker.next()
        val request = f.request()
        assertTrue(f.host.stop(request))
        assertTrue(f.host.stop(request))
        assertEquals(1, f.worker.commands.size)
        f.worker.next()
        assertEquals(1, f.runtime.stops)
        assertTrue(f.worker.timers.single().isCancelled)
        f.worker.timers.single().task.run()
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.host.snapshot().state)
    }

    @Test fun staleStopCannotAffectReplacement() {
        val f = Fixture()
        f.start()
        f.worker.next()
        val first = f.request()
        f.host.stop(first)
        f.worker.next()
        f.start()
        f.worker.next()
        assertFalse(f.host.stop(first))
        assertEquals(0, f.runtime.stops)
        assertEquals(RootHotspotServiceOwner.State.READY, f.host.snapshot().state)
    }

    @Test fun callbackDuringStartCancelsBeforeReadyAndNoTimerIsArmed() {
        val f = Fixture()
        assertTrue(f.host.start(RootHotspotAdmission.Mode.VPN) { request ->
            Runtime(request).also { r ->
                f.runtime = r
                r.duringStart = { assertTrue(f.host.stop(request)) }
            }
        })
        f.worker.next()
        assertEquals(1, f.runtime.stops)
        assertTrue(f.worker.timers.isEmpty())
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.host.snapshot().state)
    }

    @Test fun negativeHealthReportsStoppedAndNeverRestarts() {
        val f = Fixture()
        f.start()
        f.worker.next()
        f.runtime.healthy = false
        f.worker.timers.single().task.run()
        assertEquals(1, f.runtime.stops)
        assertEquals(1, f.worker.timers.size)
        assertTrue(f.worker.commands.isEmpty())
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.statuses.last().state)
    }

    @Test fun failedCleanupRemainsVisibleAndRetryUsesSameOwner() {
        val f = Fixture()
        f.start()
        f.worker.next()
        val request = f.request()
        f.runtime.stopOk = false
        f.host.stop(request)
        f.worker.next()
        assertEquals(RootHotspotServiceOwner.State.CLEANUP_PENDING, f.statuses.last().state)
        assertEquals(request, f.statuses.last().request)
        assertFalse(f.start())
        f.runtime.stopOk = true
        f.host.stop(request)
        f.worker.next()
        assertEquals(2, f.runtime.stops)
        assertEquals(RootHotspotServiceOwner.State.IDLE, f.statuses.last().state)
    }

    @Test fun rejectedStopRetainsExactOwnerForRetry() {
        val f = Fixture()
        f.start()
        f.worker.next()
        val request = f.request()
        f.worker.rejectCommands = true
        assertFalse(f.host.stop(request))
        assertEquals(request, f.host.snapshot().request)
        f.worker.rejectCommands = false
        assertTrue(f.host.stop(request))
        f.worker.next()
        assertEquals(1, f.runtime.stops)
    }
}
