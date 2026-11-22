package com.dpsmpx.dppass.connection

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class Zapret2AdaptiveTargetsTest {
    @Test fun normalizesExplicitDomainsAndIpv4() {
        assertEquals("r1.googlevideo.com", Zapret2AdaptiveTargets.normalize("R1.GoogleVideo.COM."))
        assertEquals("203.0.113.4", Zapret2AdaptiveTargets.normalize("203.0.113.4"))
        assertNull(Zapret2AdaptiveTargets.normalize("999.0.0.1"))
        assertNull(Zapret2AdaptiveTargets.normalize("--bad.example.org"))
        assertNull(Zapret2AdaptiveTargets.normalize("not a host"))
    }

    @Test fun addAndRemoveSelectedHostsWithoutRecordingOtherTraffic() {
        val first = Zapret2AdaptiveTargets.update("", "YOUTUBE.COM", true).getOrThrow()
        val second = Zapret2AdaptiveTargets.update(first, "ytimg.com", true).getOrThrow()
        assertEquals(listOf("youtube.com", "ytimg.com"), Zapret2AdaptiveTargets.parse(second).getOrThrow())
        assertEquals("ytimg.com", Zapret2AdaptiveTargets.update(second, "youtube.com", false).getOrThrow())
        assertEquals(second, Zapret2AdaptiveTargets.update(first, "ytimg.com", true).getOrThrow())
    }

    @Test fun malformedSelectionDoesNotOverwriteExistingPreferences() {
        assertTrue(Zapret2AdaptiveTargets.update("youtube.com", "bad host", true).isFailure)
        assertTrue(Zapret2AdaptiveTargets.update("bad host", "youtube.com", true).isFailure)
        assertFalse(Zapret2AdaptiveTargets.parse("youtube.com\nytimg.com").isFailure)
    }
}
