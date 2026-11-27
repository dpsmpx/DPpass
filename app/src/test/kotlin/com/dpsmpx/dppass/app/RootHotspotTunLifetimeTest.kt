package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.TunInput
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotTunLifetimeTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val exact = RootHotspotTunLifetime.Identity(session, "dpgateway", 42)
    private fun inventory(extra: String = "", address: String = "") =
        RootHotspotInterfaceEvidence.parse("1: lo: <LOOPBACK> mtu 65536\n" + extra,
            "1: lo inet 127.0.0.1/8 scope host lo\n" + address)
    private val present = inventory("42: dpgateway: <UP> mtu 1500\n")
    private val absent = inventory()

    @Test fun exactIdentityAndUnaddressedInterfaceRequired() {
        assertTrue(exact.present(present))
        assertFalse(exact.present(inventory("43: dpgateway: <UP> mtu 1500\n")))
        assertFalse(exact.present(inventory("42: other: <UP> mtu 1500\n")))
        assertFalse(exact.present(inventory("42: dpgateway: <UP> mtu 1500\n",
            "42: dpgateway inet 192.0.2.1/24 scope global dpgateway\n")))
        assertFalse(exact.present(null))
    }

    @Test fun nameOrIndexReuseIsNotRetirement() {
        assertTrue(exact.absent(absent))
        assertFalse(exact.absent(present))
        assertFalse(exact.absent(inventory("43: dpgateway: <UP> mtu 1500\n")))
        assertFalse(exact.absent(inventory("42: other: <UP> mtu 1500\n")))
        assertFalse(exact.absent(null))
    }

    @Test fun invalidIdentityRejected() {
        for ((name, index) in listOf("lo" to 42, "bad name" to 42, "dpgateway" to 12, "dpgateway" to 0)) {
            assertThrows(IllegalArgumentException::class.java) {
                RootHotspotTunLifetime.Identity(session, name, index)
            }
        }
    }

    @Test fun inputRequiresCurrentIdentityAndCannotBeUsedAfterClose() {
        var observed = present
        var opened = 0
        var closed = 0
        val tun = RootHotspotTunLifetime(exact, { opened++; TunInput(42, 1500) { true } },
            { closed++ }, { observed }, { true })
        assertEquals(42, tun.input.fd)
        assertEquals(42, tun.input.fd)
        assertEquals(1, opened)
        observed = absent
        assertThrows(IllegalStateException::class.java) { tun.input }
        assertFalse(tun.verifyClosed())
        tun.close()
        tun.close()
        assertEquals(1, closed)
        assertThrows(IllegalStateException::class.java) { tun.input }
        assertTrue(tun.verifyClosed())
    }

    @Test fun ambiguousCloseRetriesSameObjectAndNeverAllowsInputAgain() {
        var closeCount = 0
        val tun = RootHotspotTunLifetime(exact, { TunInput(42, 1500) { true } },
            { if (++closeCount == 1) error("close failed") }, { absent }, { true })
        assertThrows(IllegalStateException::class.java) { tun.close() }
        assertFalse(tun.verifyClosed())
        assertThrows(IllegalStateException::class.java) { tun.input }
        tun.close()
        assertTrue(tun.verifyClosed())
        assertEquals(2, closeCount)
    }

    @Test fun helperAndBothInventoriesMustConfirmRetirement() {
        var helper = true
        var observations = 0
        var changed = true
        val tun = RootHotspotTunLifetime(exact, { error("unused") }, {}, {
            if (++observations == 2 && changed) present else absent
        }, { helper })
        tun.close()
        assertFalse(tun.verifyClosed())
        helper = false
        assertFalse(tun.verifyClosed())
        changed = false
        helper = true
        assertTrue(tun.verifyClosed())
    }

    @Test fun interruptedRetirementProofPreservesInterrupt() {
        val tun = RootHotspotTunLifetime(exact, { error("unused") }, {},
            { throw InterruptedException() }, { true })
        tun.close()
        try {
            assertFalse(tun.verifyClosed())
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
