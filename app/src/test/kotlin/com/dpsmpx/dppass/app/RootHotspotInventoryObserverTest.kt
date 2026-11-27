package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotInterfaceEvidence.PlatformState
import com.dpsmpx.dppass.app.RootHotspotInventoryObserver.PlatformObservation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class RootHotspotInventoryObserverTest {
    private val session = RootHotspotAdmission.Session(7, 12, RootHotspotAdmission.Mode.VPN)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val loopLink = "1: lo: <UP> mtu 65536"
    private val loopAddr = "1: lo inet 127.0.0.1/8 scope host lo"
    private val apLink = "12: wlan1: <UP> mtu 1500"
    private val apAddr = "12: wlan1 inet 192.168.43.1/24 scope global wlan1"
    private val absent = PlatformObservation(session, true, PlatformState.ABSENT)

    private fun observer(vararg outputs: String): RootHotspotInventoryObserver {
        val remaining = outputs.iterator()
        return RootHotspotInventoryObserver { RootCommandRunner.CompleteResult(0, remaining.next()) }
    }

    @Test fun stableInventoryUsesTwoOrderedPairs() {
        val commands = mutableListOf<List<String>>()
        val observer = RootHotspotInventoryObserver { args ->
            commands += args
            RootCommandRunner.CompleteResult(0, if ("link" in args) loopLink else loopAddr)
        }
        assertNotNull(observer.stableInventory())
        assertEquals(listOf(listOf("ip", "-o", "link", "show"), listOf("ip", "-4", "-o", "addr", "show"),
            listOf("ip", "-o", "link", "show"), listOf("ip", "-4", "-o", "addr", "show")), commands)
    }

    @Test fun changingTopologyCannotConfirmStop() {
        assertFalse(observer(loopLink, loopAddr, "$loopLink\n$apLink", "$loopAddr\n$apAddr")
            .stopped(identity) { absent })
    }

    @Test fun failedCommandAndMalformedOutputRefuse() {
        assertNull(RootHotspotInventoryObserver { RootCommandRunner.CompleteResult(1, loopLink) }.stableInventory())
        assertNull(observer(loopLink, "broken").stableInventory())
        assertNull(RootHotspotInventoryObserver { error("capture failed") }.stableInventory())
    }

    @Test fun platformMustRemainRetiredAndSessionScoped() {
        var reads = 0
        assertFalse(observer(loopLink, loopAddr, loopLink, loopAddr).stopped(identity) {
            if (reads++ == 0) absent else absent.copy(requestRetired = false)
        })
        assertFalse(observer().stopped(identity) { absent.copy(session = session.copy(generation = 8)) })
        assertFalse(observer().stopped(identity) { absent.copy(state = PlatformState.UNKNOWN) })
    }

    @Test fun agreesWithConservativeStopEvidence() {
        assertTrue(observer(loopLink, loopAddr, loopLink, loopAddr).stopped(identity) { absent })
        assertFalse(observer("$loopLink\n$apLink", "$loopAddr\n$apAddr",
            "$loopLink\n$apLink", "$loopAddr\n$apAddr").stopped(identity) { absent })
    }

    @Test fun interruptedObservationRestoresInterrupt() {
        try {
            assertNull(RootHotspotInventoryObserver { throw InterruptedException() }.stableInventory())
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }
}
