package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotAdmission.Evidence
import com.dpsmpx.dppass.app.RootHotspotAdmission.Mode
import com.dpsmpx.dppass.app.RootHotspotAdmission.Session
import com.dpsmpx.dppass.app.RootHotspotLifecycle.StartResult
import com.dpsmpx.dppass.app.RootHotspotLifecycle.State
import com.dpsmpx.dppass.app.RootHotspotLifecycle.StopResult
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

class RootHotspotLifecycleTest {
    private fun session(generation: Long) = Session(generation, 2, Mode.VPN)
    private fun evidence(session: Session) = Evidence(true, session, session, session, session, session, session)

    @Test fun activeSessionRejectsOverlappingStartsAndForeignStops() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val second = session(2)
        var cleanupCalls = 0
        assertEquals(StartResult.READY, owner.start(first, {
            assertEquals(State.STARTING, owner.snapshot().state)
            assertEquals(StopResult.STALE, owner.stop(second))
            evidence(first)
        }, { true }, {
            cleanupCalls++
            assertEquals(State.STOPPING, owner.snapshot().state)
            assertEquals(StopResult.BUSY, owner.stop(first))
            RootHotspotShutdown.Result.STOPPED
        }))
        assertEquals(StartResult.BUSY, owner.start(second, { error("must not prepare") }, { false }, { error("must not clean") }))
        assertEquals(StopResult.STALE, owner.stop(first.copy(downstreamIndex = 3)))
        assertEquals(StopResult.STALE, owner.stop(first.copy(mode = Mode.LOCAL_STRATEGIES)))
        assertEquals(StopResult.STALE, owner.stop(second))
        assertEquals(0, cleanupCalls)
        assertEquals(StopResult.STOPPED, owner.stop(first))
        assertEquals(1, cleanupCalls)
        assertEquals(RootHotspotLifecycle.Snapshot(State.IDLE, null), owner.snapshot())
        assertEquals(StartResult.STALE, owner.start(first, { error("must not prepare") }, { false }, { error("must not clean") }))
        assertEquals(StartResult.READY, owner.start(second, { evidence(second) }, { true }, { RootHotspotShutdown.Result.STOPPED }))
        assertEquals(StopResult.STALE, owner.stop(first))
        assertEquals(StopResult.STOPPED, owner.stop(second))
    }

    @Test fun refusedStartRetainsCleanupOwnerUntilConfirmed() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        var attempts = 0
        assertEquals(StartResult.CLEANUP_PENDING, owner.start(
            first, { evidence(first).copy(confinedDns = null) }, { error("must not attach") }, {
                attempts++
                if (attempts < 3) RootHotspotShutdown.Result.GUARD_RETAINED else RootHotspotShutdown.Result.STOPPED
            },
        ))
        assertEquals(RootHotspotLifecycle.Snapshot(State.CLEANUP_PENDING, first), owner.snapshot())
        assertEquals(StartResult.BUSY, owner.start(session(2), { error("must not prepare") }, { false }, { error("must not clean") }))
        assertEquals(StopResult.CLEANUP_PENDING, owner.stop(first))
        assertEquals(StopResult.STOPPED, owner.stop(first))
        assertEquals(3, attempts)
        assertEquals(State.IDLE, owner.snapshot().state)
    }

    @Test fun failedStartWithConfirmedRollbackReleasesOwner() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val primary = IllegalStateException("attach failed")
        val caught = assertThrows(IllegalStateException::class.java) {
            owner.start(first, { evidence(first) }, { throw primary }, { RootHotspotShutdown.Result.STOPPED })
        }
        assertSame(primary, caught)
        assertEquals(State.IDLE, owner.snapshot().state)
        assertEquals(StartResult.STALE, owner.start(first, { error("must not prepare") }, { false }, { error("must not clean") }))
    }

    @Test fun cleanupExceptionRetainsOwnershipAndAllowsRetry() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val failure = IllegalStateException("stop failed")
        var attempts = 0
        assertEquals(StartResult.READY, owner.start(first, { evidence(first) }, { true }, {
            if (++attempts == 1) throw failure
            RootHotspotShutdown.Result.STOPPED
        }))
        assertSame(failure, assertThrows(IllegalStateException::class.java) { owner.stop(first) })
        assertEquals(RootHotspotLifecycle.Snapshot(State.CLEANUP_PENDING, first), owner.snapshot())
        assertEquals(StopResult.STOPPED, owner.stop(first))
        assertEquals(State.IDLE, owner.snapshot().state)
    }

    @Test fun unconfirmedExceptionalStartupRetainsExactOwner() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val primary = IllegalStateException("prepare failed")
        var attempts = 0
        assertSame(primary, assertThrows(IllegalStateException::class.java) {
            owner.start(first, { throw primary }, { error("must not attach") }, {
                if (++attempts == 1) RootHotspotShutdown.Result.CLEANUP_PENDING else RootHotspotShutdown.Result.STOPPED
            })
        })
        assertEquals(State.CLEANUP_PENDING, owner.snapshot().state)
        assertEquals(StopResult.STOPPED, owner.stop(first))
    }

    private class Pause {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)

        fun awaitRelease() {
            entered.countDown()
            check(release.await(15, TimeUnit.SECONDS)) { "fixture callback timed out" }
        }

        fun awaitEntry() = assertTrue(entered.await(5, TimeUnit.SECONDS))
    }

    @Test fun blockedPreparationDoesNotBlockSnapshotsOrCompetingRequests() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val pause = Pause()
        val pool = Executors.newFixedThreadPool(2)
        val attached = AtomicInteger()
        val cleaned = AtomicInteger()
        try {
            val start = pool.submit<StartResult> {
                owner.start(first, { pause.awaitRelease(); evidence(first) }, {
                    attached.incrementAndGet()
                    true
                }, {
                    cleaned.incrementAndGet()
                    RootHotspotShutdown.Result.STOPPED
                })
            }
            pause.awaitEntry()
            pool.submit {
                assertEquals(RootHotspotLifecycle.Snapshot(State.STARTING, first), owner.snapshot())
                assertEquals(StartResult.BUSY, owner.start(session(2), { error("competing prepare") }, { false }, { error("competing cleanup") }))
                assertEquals(StopResult.STALE, owner.stop(session(2)))
            }.get(5, TimeUnit.SECONDS)
            assertEquals(0, attached.get())
            assertEquals(0, cleaned.get())
            pause.release.countDown()
            assertEquals(StartResult.READY, start.get(5, TimeUnit.SECONDS))
            assertEquals(1, attached.get())
            assertEquals(StopResult.STOPPED, owner.stop(first))
            assertEquals(1, cleaned.get())
        } finally {
            pause.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun blockedAttachKeepsExclusiveOwnershipUntilPublication() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val pause = Pause()
        val pool = Executors.newFixedThreadPool(2)
        try {
            val start = pool.submit<StartResult> {
                owner.start(first, { evidence(first) }, { pause.awaitRelease(); true }, { RootHotspotShutdown.Result.STOPPED })
            }
            pause.awaitEntry()
            pool.submit {
                assertEquals(State.STARTING, owner.snapshot().state)
                assertEquals(StopResult.STALE, owner.stop(session(2)))
                assertEquals(StartResult.BUSY, owner.start(session(2), { error("competing prepare") }, { false }, { error("competing cleanup") }))
            }.get(5, TimeUnit.SECONDS)
            pause.release.countDown()
            assertEquals(StartResult.READY, start.get(5, TimeUnit.SECONDS))
            assertEquals(RootHotspotLifecycle.Snapshot(State.READY, first), owner.snapshot())
            assertEquals(StopResult.STOPPED, owner.stop(first))
        } finally {
            pause.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun rollbackPublishesStoppingAndRetainsOwnerWhenUnconfirmed() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val pause = Pause()
        val pool = Executors.newFixedThreadPool(2)
        val cleaned = AtomicInteger()
        try {
            val start = pool.submit<StartResult> {
                owner.start(first, { evidence(first) }, { false }, {
                    if (cleaned.incrementAndGet() == 1) {
                        pause.awaitRelease()
                        RootHotspotShutdown.Result.GUARD_RETAINED
                    } else RootHotspotShutdown.Result.STOPPED
                })
            }
            pause.awaitEntry()
            pool.submit {
                assertEquals(RootHotspotLifecycle.Snapshot(State.STOPPING, first), owner.snapshot())
                assertEquals(StopResult.BUSY, owner.stop(first))
                assertEquals(StartResult.BUSY, owner.start(session(2), { error("competing prepare") }, { false }, { error("competing cleanup") }))
            }.get(5, TimeUnit.SECONDS)
            assertEquals(1, cleaned.get())
            pause.release.countDown()
            assertEquals(StartResult.CLEANUP_PENDING, start.get(5, TimeUnit.SECONDS))
            assertEquals(RootHotspotLifecycle.Snapshot(State.CLEANUP_PENDING, first), owner.snapshot())
            assertEquals(StopResult.STOPPED, owner.stop(first))
            assertEquals(2, cleaned.get())
        } finally {
            pause.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun concurrentStopCannotRunCleanupTwiceOrReplaceOwner() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val second = session(2)
        val pause = Pause()
        val pool = Executors.newFixedThreadPool(2)
        val cleaned = AtomicInteger()
        try {
            assertEquals(StartResult.READY, owner.start(first, { evidence(first) }, { true }, {
                cleaned.incrementAndGet()
                pause.awaitRelease()
                RootHotspotShutdown.Result.STOPPED
            }))
            val stop = pool.submit<StopResult> { owner.stop(first) }
            pause.awaitEntry()
            pool.submit {
                assertEquals(RootHotspotLifecycle.Snapshot(State.STOPPING, first), owner.snapshot())
                assertEquals(StopResult.BUSY, owner.stop(first))
                assertEquals(StopResult.STALE, owner.stop(second))
                assertEquals(StartResult.BUSY, owner.start(second, { error("competing prepare") }, { false }, { error("competing cleanup") }))
            }.get(5, TimeUnit.SECONDS)
            assertEquals(1, cleaned.get())
            pause.release.countDown()
            assertEquals(StopResult.STOPPED, stop.get(5, TimeUnit.SECONDS))
            assertEquals(RootHotspotLifecycle.Snapshot(State.IDLE, null), owner.snapshot())
            assertEquals(StartResult.READY, owner.start(second, { evidence(second) }, { true }, { RootHotspotShutdown.Result.STOPPED }))
            assertEquals(StopResult.STALE, owner.stop(first))
            assertEquals(StopResult.STOPPED, owner.stop(second))
            assertEquals(1, cleaned.get())
        } finally {
            pause.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun cancelDuringPreparationPreventsAttachmentAndCleansExactlyOnce() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val pause = Pause()
        val pool = Executors.newSingleThreadExecutor()
        val cleaned = AtomicInteger()
        try {
            val start = pool.submit<StartResult> {
                owner.start(first, { pause.awaitRelease(); evidence(first) }, {
                    error("cancelled preparation must not attach")
                }, {
                    cleaned.incrementAndGet()
                    RootHotspotShutdown.Result.STOPPED
                })
            }
            pause.awaitEntry()
            assertEquals(StopResult.STALE, owner.stop(first.copy(downstreamIndex = 3)))
            assertEquals(false, owner.snapshot().cancellationRequested)
            repeat(2) { assertEquals(StopResult.CANCEL_REQUESTED, owner.stop(first)) }
            assertEquals(RootHotspotLifecycle.Snapshot(State.STARTING, first, true), owner.snapshot())
            assertEquals(0, cleaned.get())
            pause.release.countDown()
            assertEquals(StartResult.CANCELLED, start.get(5, TimeUnit.SECONDS))
            assertEquals(1, cleaned.get())
            assertEquals(RootHotspotLifecycle.Snapshot(State.IDLE, null), owner.snapshot())
            assertEquals(StartResult.STALE, owner.start(first, { error("stale") }, { false }, { error("stale") }))
        } finally {
            pause.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun cancellationDuringAttachRollsBackBeforePublishingReady() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val attach = Pause()
        val cleanup = Pause()
        val pool = Executors.newSingleThreadExecutor()
        val cleaned = AtomicInteger()
        try {
            val start = pool.submit<StartResult> {
                owner.start(first, { evidence(first) }, { attach.awaitRelease(); true }, {
                    cleaned.incrementAndGet()
                    cleanup.awaitRelease()
                    RootHotspotShutdown.Result.STOPPED
                })
            }
            attach.awaitEntry()
            assertEquals(StopResult.CANCEL_REQUESTED, owner.stop(first))
            attach.release.countDown()
            cleanup.awaitEntry()
            assertEquals(RootHotspotLifecycle.Snapshot(State.STOPPING, first, true), owner.snapshot())
            assertEquals(StopResult.BUSY, owner.stop(first))
            assertEquals(StartResult.BUSY, owner.start(session(2), { error("busy") }, { false }, { error("busy") }))
            cleanup.release.countDown()
            assertEquals(StartResult.CANCELLED, start.get(5, TimeUnit.SECONDS))
            assertEquals(1, cleaned.get())
            assertEquals(State.IDLE, owner.snapshot().state)
        } finally {
            attach.release.countDown()
            cleanup.release.countDown()
            pool.shutdownNow()
        }
    }

    @Test fun cancelledAttachWithUnconfirmedCleanupRetainsOwnerForRetry() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        var attempts = 0
        assertEquals(StartResult.CLEANUP_PENDING, owner.start(first, { evidence(first) }, {
            assertEquals(StopResult.CANCEL_REQUESTED, owner.stop(first))
            true
        }, {
            if (++attempts == 1) RootHotspotShutdown.Result.GUARD_RETAINED else RootHotspotShutdown.Result.STOPPED
        }))
        assertEquals(RootHotspotLifecycle.Snapshot(State.CLEANUP_PENDING, first, true), owner.snapshot())
        assertEquals(StopResult.STOPPED, owner.stop(first))
        assertEquals(2, attempts)
        assertEquals(RootHotspotLifecycle.Snapshot(State.IDLE, null), owner.snapshot())
    }

    @Test fun cancelledAttachWithCleanupExceptionRetainsOriginalFailureAndOwner() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val failure = IllegalStateException("cancel cleanup failed")
        var attempts = 0
        val caught = assertThrows(IllegalStateException::class.java) {
            owner.start(first, { evidence(first) }, {
                assertEquals(StopResult.CANCEL_REQUESTED, owner.stop(first))
                true
            }, {
                if (++attempts == 1) throw failure
                RootHotspotShutdown.Result.STOPPED
            })
        }
        assertSame(failure, caught)
        assertEquals(RootHotspotLifecycle.Snapshot(State.CLEANUP_PENDING, first, true), owner.snapshot())
        assertEquals(StopResult.STOPPED, owner.stop(first))
        assertEquals(2, attempts)
    }

    @Test fun cancellationDoesNotHidePreparationFailure() {
        val owner = RootHotspotLifecycle()
        val first = session(1)
        val failure = IllegalStateException("prepare failed")
        var cleaned = 0
        assertSame(failure, assertThrows(IllegalStateException::class.java) {
            owner.start(first, {
                assertEquals(StopResult.CANCEL_REQUESTED, owner.stop(first))
                throw failure
            }, { error("must not attach") }, {
                cleaned++
                RootHotspotShutdown.Result.STOPPED
            })
        })
        assertEquals(1, cleaned)
        assertEquals(State.IDLE, owner.snapshot().state)
    }
}
