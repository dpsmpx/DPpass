package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotForwardGuardTest {
    private val guard = RootHotspotForwardGuard("wlan1", "dpgateway", "0123456789abcdef")

    @Test fun blocksBothFamiliesBeforeAttachAndOpensOnlyIpv4TunPair() {
        assertEquals(4, guard.install.size)
        assertTrue(guard.install.all { it.endsWith("-j DROP") && "dppass-hotspot-0123456789abcdef" in it })
        assertEquals(2, guard.install.count { it.startsWith("ip6tables ") })
        assertEquals(2, guard.attach.size)
        assertTrue(guard.attach.all { it.startsWith("iptables ") && "dpgateway" in it && it.endsWith("-j ACCEPT") })
        assertFalse((guard.attach + guard.detach).any { it.startsWith("ip6tables") })
        assertEquals(guard.attach.map { it.replace(" -I FORWARD 1 ", " -D FORWARD ") }, guard.detach)
        assertEquals(guard.install.map { it.replace(" -I FORWARD 1 ", " -D FORWARD ") }, guard.retireAfterAccessPointStopped)
    }

    @Test fun rejectsUnsafeNames() {
        for ((down, tun, gen) in listOf(
            Triple("lo", "dpgateway", "0123456789abcdef"),
            Triple("wlan1", "wlan1", "0123456789abcdef"),
            Triple("wlan1;id", "dpgateway", "0123456789abcdef"),
            Triple("wlan1", "dpgateway", "XYZ"),
        )) {
            assertTrue(runCatching { RootHotspotForwardGuard(down, tun, gen) }.isFailure)
        }
    }
}
