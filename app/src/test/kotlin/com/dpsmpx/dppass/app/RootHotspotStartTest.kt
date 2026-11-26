package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertSame
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RootHotspotStartTest {
    @Test fun attachesOnlyWithCurrentEvidenceAndRetainsPendingCleanup() {
        val session = RootHotspotAdmission.Session(1, 2, RootHotspotAdmission.Mode.VPN)
        val ready = RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)
        val calls = mutableListOf<String>()
        assertEquals(RootHotspotStart.Result.CLEANUP_PENDING, RootHotspotStart.run(
            session, { ready.copy(confinedDns = null) }, { error("must not attach") },
            { calls += "shutdown"; RootHotspotShutdown.Result.GUARD_RETAINED },
        ))
        assertEquals(RootHotspotStart.Result.READY, RootHotspotStart.run(
            session, { ready }, { calls += "attach"; true }, { error("must not shut down") },
        ))
        assertEquals(RootHotspotStart.Result.REFUSED, RootHotspotStart.run(
            session, { ready }, { false }, { RootHotspotShutdown.Result.STOPPED },
        ))
        assertEquals(listOf("shutdown", "attach"), calls)
    }

    @Test fun failedAttachRetainsOriginalFailureAndUnconfirmedCleanup() {
        val session = RootHotspotAdmission.Session(1, 2, RootHotspotAdmission.Mode.VPN)
        val ready = RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)
        val primary = IllegalStateException("attach failed")
        var cleanupCalls = 0
        val caught = assertThrows(IllegalStateException::class.java) {
            RootHotspotStart.run(session, { ready }, { throw primary }, {
                cleanupCalls++
                RootHotspotShutdown.Result.GUARD_RETAINED
            })
        }
        assertSame(primary, caught)
        assertEquals(1, cleanupCalls)
        assertEquals("ROOT hotspot cleanup unconfirmed: GUARD_RETAINED", caught.suppressed.single().message)
    }

    @Test fun preparationFailureStillAttemptsCleanupAndPreservesBothFailures() {
        val session = RootHotspotAdmission.Session(1, 2, RootHotspotAdmission.Mode.LOCAL_STRATEGIES)
        val primary = AssertionError("prepare failed")
        val cleanup = IllegalStateException("cleanup failed")
        val caught = assertThrows(AssertionError::class.java) {
            RootHotspotStart.run(session, { throw primary }, { error("must not attach") }, { throw cleanup })
        }
        assertSame(primary, caught)
        assertSame(cleanup, caught.suppressed.single())
    }
}
