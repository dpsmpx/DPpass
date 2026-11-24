package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootDpiPreflightTest {
    @Test fun experimentalPackageCannotUseSharedLegacyRootState() {
        assertFalse(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass.alpine.localdpi"))
        assertTrue(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass"))
        assertTrue(RootDpiPreflight.permitsLegacyRoot("com.dpsmpx.dppass.alpine"))
    }

    @Test fun rootPreflightChecksOnlyRequiredTableAndEffectiveUid() {
        val socket = RootDpiPreflight.script(RootDpiPreflight.Kind.SOCKET)
        val packet = RootDpiPreflight.script(RootDpiPreflight.Kind.PACKET)
        assertTrue(socket.contains("id -u"))
        assertTrue(packet.contains("id -u"))
        assertTrue(socket.contains("iptables -t nat -S OUTPUT"))
        assertTrue(packet.contains("iptables -t mangle -S OUTPUT"))
        for (script in listOf(socket, packet)) {
            for (forbidden in listOf(" -I ", " -A ", " -D ", " -F ", " -N ", "kill ", "mkdir ", "rm ")) {
                assertFalse(script.contains(forbidden), forbidden)
            }
        }
        assertFalse(socket.contains("mangle"))
        assertFalse(packet.contains(" nat "))
    }
}
