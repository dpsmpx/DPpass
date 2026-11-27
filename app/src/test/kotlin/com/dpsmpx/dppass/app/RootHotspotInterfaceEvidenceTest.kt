package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.app.RootHotspotAdmission.Mode
import com.dpsmpx.dppass.app.RootHotspotAdmission.Session
import com.dpsmpx.dppass.app.RootHotspotInterfaceEvidence.PlatformState
import com.dpsmpx.dppass.app.RootHotspotInterfaceEvidence.StopObservation
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotNull
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotInterfaceEvidenceTest {
    private val session = Session(7, 12, Mode.VPN)
    private val gateway = "192.168.43.1"
    private val loopLink = "1: lo: <LOOPBACK,UP> mtu 65536"
    private val loopAddr = "1: lo    inet 127.0.0.1/8 scope host lo"
    private val apLink = "12: wlan1: <BROADCAST,UP> mtu 1500"
    private val apAddr = "12: wlan1    inet $gateway/24 scope global wlan1"
    private val otherLink = "19: wlan0: <BROADCAST,UP> mtu 1500"
    private val otherAddr = "19: wlan0    inet 10.0.0.2/24 scope global wlan0"

    private fun inventory(vararg links: String, addresses: List<String>) =
        RootHotspotInterfaceEvidence.parse(
            (listOf(loopLink) + links).joinToString("\n", postfix = "\n"),
            (listOf(loopAddr) + addresses).joinToString("\n", postfix = "\n"),
        )

    private fun identity() = checkNotNull(RootHotspotInterfaceEvidence.discover(
        session, inventory(apLink, otherLink, addresses = listOf(apAddr, otherAddr)),
        setOf("wlan1"), gateway,
    ))

    @Test fun discoversExactIndexAndUniquePrivateGateway() {
        val inventory = inventory(apLink, otherLink, addresses = listOf(apAddr, otherAddr))
        assertEquals(12, inventory?.indexOf("wlan1"))
        assertEquals("wlan1", inventory?.nameOf(12))
        assertEquals(setOf(gateway), inventory?.ipv4("wlan1"))
        assertEquals(RootHotspotInterfaceEvidence.Identity(session, "wlan1", gateway),
            RootHotspotInterfaceEvidence.discover(session, inventory, setOf("wlan1"), gateway))
        assertNull(RootHotspotInterfaceEvidence.discover(session.copy(downstreamIndex = 19),
            inventory, setOf("wlan1"), gateway))
    }

    @Test fun rejectsAmbiguousPlatformAndGatewayOwnership() {
        val normal = inventory(apLink, otherLink, addresses = listOf(apAddr, otherAddr))
        for (names in listOf(emptySet(), setOf("wlan0"), setOf("wlan1", "wlan0"))) {
            assertNull(RootHotspotInterfaceEvidence.discover(session, normal, names, gateway))
        }
        val duplicate = inventory(apLink, otherLink, addresses = listOf(apAddr, otherAddr.replace("10.0.0.2", gateway)))
        assertNull(RootHotspotInterfaceEvidence.discover(session, duplicate, setOf("wlan1"), gateway))
        for (bad in listOf("8.8.8.8", "127.0.0.1", "192.168.043.1", "192.168.43.256")) {
            assertNull(RootHotspotInterfaceEvidence.discover(session, normal, setOf("wlan1"), bad))
        }
    }

    @Test fun malformedOrInconsistentInventoryIsNotEvidence() {
        for (links in listOf(null, "", apLink, "$loopLink\n$apLink\n$apLink",
            "$loopLink\n$apLink\n12: wlan0: <UP> mtu 1500", "$loopLink\n12: wlan1;: <UP>",
            "$loopLink\n2147483648: wlan1: <UP>", "$loopLink\n" + "x".repeat(256 * 1024))) {
            assertNull(RootHotspotInterfaceEvidence.parse(links, "$loopAddr\n$apAddr"))
        }
        for (addresses in listOf(null, "", apAddr, "$loopAddr\n$apAddr\nunknown",
            "$loopAddr\n" + apAddr.replace("12:", "19:"),
            "$loopAddr\n" + apAddr.replace("/24", "/33"),
            "$loopAddr\n" + apAddr.replace(gateway, "192.168.43.999"))) {
            assertNull(RootHotspotInterfaceEvidence.parse("$loopLink\n$apLink", addresses))
        }
    }

    @Test fun acceptsLinkedInterfaceSuffixWithoutConfusingIdentity() {
        val inventory = inventory("12: wlan1@if9: <BROADCAST,UP> mtu 1500",
            addresses = listOf(apAddr.replace("wlan1    ", "wlan1@if9    ")))
        assertNotNull(inventory)
        assertEquals(12, inventory?.indexOf("wlan1"))
        assertEquals(setOf(gateway), inventory?.ipv4("wlan1"))
    }

    @Test fun confirmsOnlyMatchingRetiredInactiveOrAbsentInterface() {
        val identity = identity()
        val absent = inventory(otherLink, addresses = listOf(otherAddr))
        val inactive = inventory(apLink, otherLink, addresses = listOf(otherAddr))
        assertTrue(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.ABSENT, absent)))
        assertTrue(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.INACTIVE, inactive)))
        assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, false, PlatformState.ABSENT, absent)))
        assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session.copy(generation = 8), true, PlatformState.ABSENT, absent)))
        assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.ABSENT, inactive)))
        assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.INACTIVE, absent)))
    }

    @Test fun refusesUnknownActiveOrFailedPlatformObservation() {
        val identity = identity()
        val absent = inventory(addresses = emptyList())
        for (state in listOf(PlatformState.UNKNOWN, PlatformState.LOCAL_ONLY, PlatformState.OTHER)) {
            assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, state, absent)))
        }
        assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.ABSENT, null)))
    }

    @Test fun refusesNameOrIndexReuseAndMigratedGateway() {
        val identity = identity()
        val cases = listOf(
            inventory("19: wlan1: <UP> mtu 1500", addresses = emptyList()),
            inventory("12: wlan2: <UP> mtu 1500", addresses = emptyList()),
            inventory("19: wlan1: <UP> mtu 1500", "12: wlan2: <UP> mtu 1500", addresses = emptyList()),
            inventory(otherLink, addresses = listOf(otherAddr.replace("10.0.0.2", gateway))),
        )
        for (inventory in cases) for (state in listOf(PlatformState.INACTIVE, PlatformState.ABSENT)) {
            assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, state, inventory)))
        }
    }

    @Test fun retainedInterfaceWithAnyIpv4AddressIsNotStopped() {
        val identity = identity()
        for (address in listOf(apAddr, apAddr.replace(gateway, "192.168.44.1"))) {
            val inventory = inventory(apLink, addresses = listOf(address))
            assertFalse(RootHotspotInterfaceEvidence.stopped(identity, StopObservation(session, true, PlatformState.INACTIVE, inventory)))
        }
    }
}
