package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotReadinessTest {
    @Test fun failedRootBaselineNeverExecutesOtherQueries() {
        var calls = 0
        val root = RootHotspotRootAccess({ _, _ ->
            calls++
            RootCommandRunner.CompleteResult(1, "")
        })
        val report = RootHotspotReadiness(root).inspect()
        assertEquals(1, calls)
        assertEquals(RootHotspotReadiness.Check.entries.toSet(), report.failed)
        assertFalse(report.activationAllowed)
    }

    @Test fun fullReadOnlyObservationsStillNeverAuthorizeActivation() {
        val root = RootHotspotRootAccess({ args, _ ->
            val script = args.last()
            val output = when {
                "baseline_available" in script -> "baseline_available\n"
                "printf 'present" in script -> "absent\n"
                "dumpsys tethering --short" in script -> "Tethering:\nTether state:\nUpstream wanted: false\n" +
                    "Current upstream interface(s): null\nHardware offload:\nfixture\nLog:\n<log removed for brevity>\n"
                "ip -o link show" in script -> "1: lo: <LOOPBACK> mtu 65536\n"
                "ip -4 -o addr show" in script -> "1: lo inet 127.0.0.1/8 scope host lo\n"
                else -> error("unexpected mutation")
            }
            RootCommandRunner.CompleteResult(0, output)
        })
        val report = RootHotspotReadiness(root).inspect()
        assertTrue(report.observationsReady)
        assertFalse(report.activationAllowed)
    }
}
