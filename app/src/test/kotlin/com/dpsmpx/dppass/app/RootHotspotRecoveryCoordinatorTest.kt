package com.dpsmpx.dppass.app

import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class RootHotspotRecoveryCoordinatorTest {
    private val record = RootHotspotOwnerRecord(9, RootHotspotAdmission.Mode.VPN, null,
        UUID.randomUUID(), RootHotspotOwner(RootOwnerIdentity(123, "456"), UUID.randomUUID()),
        RootHotspotNetworkFixture.slot)
    private val present = RootHotspotRootAccess.ClaimState.Present(record)

    @Test fun absentUnknownAndLiveOwnerNeverInvokeCleanupProvider() {
        for ((state, result) in listOf(
            RootHotspotRootAccess.ClaimState.Absent to RootHotspotRecovery.Outcome.ABSENT,
            RootHotspotRootAccess.ClaimState.Unknown to RootHotspotRecovery.Outcome.UNKNOWN,
            present to RootHotspotRecovery.Outcome.OWNER_UNCONFIRMED,
        )) {
            val recovery = RootHotspotRecovery({ state }, { RootHotspotClaim.fromRecord(it) }, { false })
            assertEquals(result, recovery.recover(null) { error("no cleanup proof allowed") })
        }
    }

    @Test fun requiresProofForExactRecordAndRejectsChangedRecord() {
        var state: RootHotspotRootAccess.ClaimState = present
        var executions = 0
        val recovery = RootHotspotRecovery({ state }, { RootHotspotClaim.fromRecord(it) }, { executions++; true })
        assertEquals(RootHotspotRecovery.Outcome.EVIDENCE_REQUIRED, recovery.recover(null) { null })
        assertEquals(1, executions)
        assertEquals(RootHotspotRecovery.Outcome.CLEANUP_PENDING, recovery.recover(null) {
            assertEquals(record, it)
            state = RootHotspotRootAccess.ClaimState.Present(record.copy(token = UUID.randomUUID()))
            ":"
        })
        assertEquals(2, executions)
    }

    @Test fun requiresSuccessfulMutationAndConfirmedAbsence() {
        var state: RootHotspotRootAccess.ClaimState = present
        var executions = 0
        var remove = false
        val recovery = RootHotspotRecovery({ state }, { RootHotspotClaim.fromRecord(it) }, {
            executions++
            if (executions % 2 == 0 && remove) state = RootHotspotRootAccess.ClaimState.Absent
            true
        })
        assertEquals(RootHotspotRecovery.Outcome.CLEANUP_PENDING, recovery.recover(null) { ":" })
        remove = true
        assertEquals(RootHotspotRecovery.Outcome.RECOVERED, recovery.recover(null) { ":" })
        assertEquals(4, executions)
    }
}
