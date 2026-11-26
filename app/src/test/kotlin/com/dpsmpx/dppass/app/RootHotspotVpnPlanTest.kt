package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.core.Host
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotVpnPlanTest {
    @Test fun loopbackAndUnspecifiedAreNotRemoteSubscriptionEndpoints() {
        for (value in listOf("localhost", "x.localhost.", "127.1.2.3", "0.0.0.0", "::", "::1")) {
            assertTrue(RootHotspotVpnPlan.isLocalPlaceholder(checkNotNull(Host.parse(value))), value)
        }
        for (value in listOf("vpn.example", "192.0.2.1", "192.168.1.1", "2001:db8::1")) {
            assertFalse(RootHotspotVpnPlan.isLocalPlaceholder(checkNotNull(Host.parse(value))), value)
        }
    }
}
