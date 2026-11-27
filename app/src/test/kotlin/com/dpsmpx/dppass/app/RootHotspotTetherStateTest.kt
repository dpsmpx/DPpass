package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotTetherStateTest {
    private fun dump(vararg rows: String, upstream: Boolean = false): String =
        (listOf("Tethering:", " Configuration:", " Entitlement:", " Tether state:") +
            rows.map { "  $it" } +
            listOf("  Upstream wanted: $upstream", "  Current upstream interface(s): null",
                " Hardware offload:", "  fixture", " BPF offload:", " Log:", "  <log removed for brevity>"))
            .joinToString("\n", postfix = "\n")

    @Test fun distinguishesLocalOnlyFromRegularTethering() {
        val state = requireNotNull(RootHotspotTetherState.parse(dump(
            "wlan1 - LocalHotspotState - lastError = 0",
            "rndis0 - TetheredState - lastError = 0", upstream = true)))
        assertEquals(setOf("wlan1"), state.localOnly)
        assertEquals(RootHotspotTetherState.State.TETHERED, state.interfaces["rndis0"])
        assertFalse(state.idle)
    }

    @Test fun validEmptyAndInactiveSnapshotsAreNotMissingEvidence() {
        for (raw in listOf(dump(), dump("wlan1 - AvailableState - lastError = 0",
            "rndis0 - UnavailableState - lastError = 0"))) {
            val state = requireNotNull(RootHotspotTetherState.parse(raw))
            assertTrue(state.idle)
            assertTrue(state.localOnly.isEmpty())
        }
        assertFalse(requireNotNull(RootHotspotTetherState.parse(dump(upstream = true))).idle)
    }

    @Test fun onlySingleLocalOnlyWithoutAnyUpstreamIsACandidate() {
        val local = "wlan1 - LocalHotspotState - lastError = 0"
        val second = "wlan2 - LocalHotspotState - lastError = 0"
        val tethered = "rndis0 - TetheredState - lastError = 0"
        assertEquals("wlan1", RootHotspotTetherState.parse(dump(local))?.isolatedLocalOnly)
        for (raw in listOf(dump(local, second), dump(local, tethered), dump(local, upstream = true),
            dump(local).replace("interface(s): null", "interface(s): [rmnet0]"))) {
            assertNull(requireNotNull(RootHotspotTetherState.parse(raw)).isolatedLocalOnly)
        }
        assertFalse(requireNotNull(RootHotspotTetherState.parse(
            dump().replace("interface(s): null", "interface(s): [rmnet0]"))).idle)
    }

    @Test fun shortDumpRequiresTerminalSentinelAndNoUnexpectedTail() {
        val good = dump()
        for (raw in listOf(good.substringBefore("  <log removed for brevity>"),
            good.replace("<log removed for brevity>", "<unexpected>"),
            good + "unparsed extra content\n",
            good.replace("interface(s): null", "interface(s): "))) {
            assertNull(RootHotspotTetherState.parse(raw))
        }
    }

    @Test fun rejectsUnrecognizedAndDuplicateInterfaceRows() {
        for (rows in listOf(
            arrayOf("wlan1 - UnknownState - lastError = 0"),
            arrayOf("wlan1 - LocalHotspotState - lastError = 2"),
            arrayOf("wlan1 - AvailableState - lastError = 0", "wlan1 - LocalHotspotState - lastError = 0"),
            arrayOf("lo - LocalHotspotState - lastError = 0"),
            arrayOf("unexpected row"),
        )) assertNull(RootHotspotTetherState.parse(dump(*rows)))
    }

    @Test fun refusesIncompletePermissionDeniedOrTimedOutDumps() {
        val good = dump()
        for (raw in listOf("", good.trimEnd(), good.substringBefore(" Hardware offload:"),
            good.replace("Tether state:", "Unknown:"),
            good.replace(" Log:", " Other:"), good + "Dump timeout after 1000ms\n",
            good + "Permission Denial: can't dump.\n", good + "x".repeat(256 * 1024))) {
            assertNull(RootHotspotTetherState.parse(raw))
        }
    }

    @Test fun stableObserverRequiresTwoSuccessfulIdenticalSnapshots() {
        val first = dump("wlan1 - LocalHotspotState - lastError = 0")
        var calls = 0
        val stable = RootHotspotTetherObserver { args ->
            assertEquals(listOf("dumpsys", "tethering", "--short"), args)
            calls++
            RootCommandRunner.CompleteResult(0, first)
        }
        assertEquals(setOf("wlan1"), stable.stable()?.localOnly)
        assertEquals(2, calls)
        calls = 0
        assertNull(RootHotspotTetherObserver {
            RootCommandRunner.CompleteResult(0, if (calls++ == 0) first else dump())
        }.stable())
        calls = 0
        assertNull(RootHotspotTetherObserver {
            RootCommandRunner.CompleteResult(0, if (calls++ == 0) first
                else first.replace("interface(s): null", "interface(s): [rmnet0]"))
        }.stable())
        assertNull(RootHotspotTetherObserver { RootCommandRunner.CompleteResult(1, first) }.stable())
        assertNull(RootHotspotTetherObserver { error("unavailable") }.stable())
    }

    @Test fun observerPreservesThreadInterruption() {
        try {
            assertNull(RootHotspotTetherObserver { throw InterruptedException() }.stable())
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
