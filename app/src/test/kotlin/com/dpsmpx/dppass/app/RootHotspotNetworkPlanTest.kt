package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotNetworkPlanTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val plan = RootHotspotNetworkPlan(identity, "dpgateway", RootHotspotNetworkFixture.slot, "0123456789abcdef")

    @Test fun installDropsBeforeRoutingAndDoesNotAllowForwarding() {
        val script = plan.guard()
        assertTrue(script.indexOf("-I FORWARD 1 -i wlan1") < script.indexOf("ip -4 rule add"))
        assertTrue(script.contains("ip6tables -t filter -I FORWARD 1 -o wlan1"))
        assertFalse(script.contains("-I FORWARD 1 -i wlan1 -o dpgateway"))
        assertTrue(script.contains("|| exit 1"))
    }

    @Test fun attachDnsAndRouteBeforeForwarding() {
        val script = plan.attach()
        assertTrue(script.indexOf("DNAT") < script.indexOf("route add default dev"))
        assertTrue(script.indexOf("route add default dev") < script.indexOf("-I FORWARD"))
        assertFalse(script.contains("ip6tables"))
        assertFalse(script.contains("MASQUERADE"))
    }

    @Test fun detachIsExactBoundedAndRetainsGuards() {
        val script = plan.detach()
        assertTrue(script.contains("remaining=32"))
        assertTrue(script.contains("iptables -t filter -C FORWARD"))
        assertTrue(script.contains("unreachable default metric 32767"))
        assertFalse(script.contains("rule del"))
        assertFalse(script.contains("-D INPUT"))
        assertFalse(script.contains("-F "))
    }

    @Test fun retireIncludesExactRulesAndFinalVacancyProof() {
        val script = plan.retire()
        assertTrue(script.contains("ip -4 rule del iif wlan1 priority"))
        assertTrue(script.contains("ip6tables -t filter -D FORWARD"))
        assertTrue(script.contains("iptables -t filter -D INPUT"))
        assertTrue(script.contains("rule show table"))
        assertFalse(script.contains("route flush"))
    }

    @Test fun rejectsInvalidTunOrMarker() {
        assertThrows(IllegalArgumentException::class.java) {
            RootHotspotNetworkPlan(identity, "wlan1", plan.slot, "0123456789abcdef")
        }
        assertThrows(IllegalArgumentException::class.java) {
            RootHotspotNetworkPlan(identity, "dpgateway", plan.slot, "bad")
        }
    }
}
