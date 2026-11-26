package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
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
}
