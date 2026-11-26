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
import org.junit.jupiter.api.Test

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
            assertEquals(StopResult.BUSY, owner.stop(first))
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
}
