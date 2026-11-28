package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Test

class DptsSessionTest {
    @Test fun sameNetworkTypeAloneDoesNotIdentifyASession() {
        val original = DptsSession.capture("WIFI", 42L, 7L)
        assertEquals(original, DptsSession.capture("WIFI", 42L, 7L))
        assertNotEquals(original, DptsSession.capture("WIFI", 43L, 7L))
        assertNotEquals(original, DptsSession.capture("WIFI", 42L, 8L))
        assertNotEquals(original, DptsSession.capture("MOBILE", 42L, 7L))
    }

    @Test fun offlineSessionRequiresIdleAndDistinctRevision() {
        val idle = TunnelState.StatusSnapshot(TunnelStatus.Idle, 42L)
        val original = DptsSession.offline(idle, 7L)
        assertEquals(true, original?.offline)
        assertEquals(original, DptsSession.offline(idle, 7L))
        assertNotEquals(original, DptsSession.offline(idle.copy(revision = 43L), 7L))
        assertNotEquals(original, DptsSession.offline(idle, 8L))
        assertNotEquals(original, DptsSession.capture("LOCAL", 42L, 7L))
        assertNull(DptsSession.offline(idle.copy(status = TunnelStatus.Connecting(null)), 7L))
        assertNull(DptsSession.offline(idle.copy(status = TunnelStatus.Stopping), 7L))
        assertNull(DptsSession.offline(idle, null))
    }

    @Test fun absentNetworkOrNativeGenerationCannotAdmitDiagnostic() {
        assertNull(DptsSession.capture("WIFI", null, 7L))
        assertNull(DptsSession.capture("WIFI", 42L, null))
        assertNull(DptsSession.capture("WIFI", 42L, -1L))
    }
}
