package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotAdmission.Evidence
import com.dpsmpx.dppass.app.RootHotspotAdmission.Mode
import com.dpsmpx.dppass.app.RootHotspotAdmission.Refusal
import com.dpsmpx.dppass.app.RootHotspotAdmission.Session
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RootHotspotAdmissionTest {
    @Test fun baselineAloneNeverAdmitsAndAllProofsMustMatchTheSession() {
        for (mode in Mode.entries) {
            val session = Session(2, 3, mode)
            val old = session.copy(generation = 1)
            val wrongMode = session.copy(mode = Mode.entries.first { it != mode })
            val complete = Evidence(true, session, session, session, session, session, session)
            assertEquals(null, RootHotspotAdmission.refusal(session, complete))
            val cases = listOf(
                Refusal.ROOT_BASELINE to complete.copy(rootBaseline = false),
                Refusal.ACCESS_POINT to Evidence(true, null, null, null, null, null, null),
                Refusal.ACCESS_POINT to complete.copy(ownedLocalOnlyWifi = session.copy(downstreamIndex = 4)),
                Refusal.OFFLOAD to complete.copy(noOffloadBypass = old),
                Refusal.GUARD to complete.copy(defaultDenyGuard = old),
                Refusal.EGRESS to complete.copy(verifiedEgress = wrongMode),
                Refusal.DNS to complete.copy(confinedDns = null),
                Refusal.IPV6 to complete.copy(blockedIpv6 = null),
            )
            for ((refusal, evidence) in cases) {
                assertEquals(refusal, RootHotspotAdmission.refusal(session, evidence))
            }
        }
    }
}
