package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.connection.Zapret2Backend
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootDpiPreflightTest {
    private val socket = RootDpiPreflight.Kind.SOCKET
    private val packet = RootDpiPreflight.Kind.PACKET
    private val all = RootCapabilitySurvey.Report(true, true, true, true, true, true)

    @Test fun experimentalPackageCannotUseSharedLegacyRootState() {
        assertFalse(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass.alpine.localdpi"))
        assertTrue(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass"))
        assertTrue(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass.alpine"))
    }

    @Test fun onlyExplicitRootSelectionsResolveToRootExecutors() {
        assertEquals(socket, RootDpiPreflight.kind(Zapret2Backend.BYEDPI_ROOT))
        assertEquals(packet, RootDpiPreflight.kind(Zapret2Backend.ROOT))
        for (backend in Zapret2Backend.entries.filterNot { it.rooted }) {
            assertNull(RootDpiPreflight.kind(backend))
        }
    }

    @Test fun independentPrerequisitesDoNotInventExecutorSupport() {
        for (kind in RootDpiPreflight.Kind.entries) {
            assertNull(RootDpiPreflight.refusal(kind, all))
            assertTrue(RootDpiPreflight.refusal(kind, null) != null)
            assertEquals("ROOT: требуется CAP_NET_ADMIN",
                RootDpiPreflight.refusal(kind, all.copy(netAdmin = false)))
            assertNull(RootDpiPreflight.refusal(kind, all.copy(ipv6Nat = false, ipv6Mangle = false)))
        }
        assertNull(RootDpiPreflight.refusal(socket, all.copy(netRaw = false, ipv4Mangle = false)))
        assertEquals("ROOT: требуется CAP_NET_RAW",
            RootDpiPreflight.refusal(packet, all.copy(netRaw = false)))
        assertEquals("ROOT: недоступна IPv4 NAT OUTPUT",
            RootDpiPreflight.refusal(socket, all.copy(ipv4Nat = false)))
        assertNull(RootDpiPreflight.refusal(packet, all.copy(ipv4Nat = false)))
        assertEquals("ROOT: недоступна IPv4 mangle OUTPUT",
            RootDpiPreflight.refusal(packet, all.copy(ipv4Mangle = false)))
    }

    @Test fun everyStartReadsFreshCapabilitiesAndRefusesBeforeLaunch() {
        var reads = 0
        var launches = 0
        fun start(report: RootCapabilitySurvey.Report?) {
            RootDpiPreflight.requireReady(packet) { reads++; report }
            launches++
        }
        start(all)
        assertThrows(IllegalStateException::class.java) { start(all.copy(netRaw = false)) }
        assertThrows(IllegalStateException::class.java) { start(null) }
        assertEquals(3, reads)
        assertEquals(1, launches)
    }
}
