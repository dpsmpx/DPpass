package com.dpsmpx.dppass.app

import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotTunLaunchTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val claim = RootHotspotClaim(session, owner = RootHotspotOwner(
        RootOwnerIdentity(123, "456"), UUID.randomUUID()), networkSlot = RootHotspotNetworkFixture.slot)
    private val socket = "/data/user/0/com.dpsmpx.dppass/cache/root-tun.sock"
    private val source = "/data/user/0/com.dpsmpx.dppass/no_backup/root-helper.bin"
    private val digest = "a".repeat(64)

    @Test fun exactCanonicalReceiptBindsSessionPeerAndInterface() {
        val receipt = checkNotNull(RootHotspotTunLaunch.parse(session, "tun_sent 1234 42\n"))
        assertEquals(1234, receipt.helperPid)
        assertEquals(RootHotspotTunLifetime.Identity(session, "dpgateway", 42), receipt.identity)
    }

    @Test fun rejectsAmbiguousOrMalformedReceipt() {
        for (raw in listOf("", "tun_sent\n", "tun_unconfirmed\n", "tun_sent 1234 42",
            "tun_sent 1234 42\n\n", "tun_sent 1234 42\nextra\n", "tun_sent 01234 42\n",
            "tun_sent 1 42\n", "tun_sent 1234 0\n", "tun_sent 1234 12\n",
            "tun_sent 1234 +42\n", "tun_sent 1234 2147483648\n", "tun_sent 1234 42\r\n")) {
            assertNull(RootHotspotTunLaunch.parse(session, raw), raw)
        }
    }

    @Test fun launchUsesExactClaimAndNoDetachedProcess() {
        val cmd = claim.tunLaunch(socket, 10000, source, digest)
        assertEquals(session, cmd.session)
        assertTrue(cmd.script.contains("flock -x -n 9"))
        assertTrue(cmd.script.contains("hotspot.owner"))
        assertTrue(cmd.script.contains("sha256sum"))
        assertTrue(cmd.script.contains("tun-send '$socket' 10000 123"))
        assertTrue(cmd.script.indexOf("hotspot.owner") < cmd.script.indexOf("tun-send"))
        assertFalse(cmd.script.contains("9>&- &"))
        assertFalse(cmd.script.contains("ip route add"))
    }

    @Test fun pendingClaimCannotLaunchHelper() {
        val pending = RootHotspotClaim.pending(session.generation, session.mode,
            RootHotspotOwner(RootOwnerIdentity(123, "456"), UUID.randomUUID()), RootHotspotNetworkFixture.slot)
        assertThrows(IllegalStateException::class.java) { pending.tunLaunch(socket, 10000, source, digest) }
    }

    @Test fun invalidSocketAndUidRejectedBeforeBuildingCommand() {
        for (bad in listOf("relative", "/", "/a//b", "/a/../b", "/a/./b", "/a b", "/a\nb", "/" + "x".repeat(108))) {
            assertThrows(IllegalArgumentException::class.java) { claim.tunLaunch(bad, 10000, source, digest) }
        }
        assertThrows(IllegalArgumentException::class.java) { claim.tunLaunch(socket, 0, source, digest) }
    }

    @Test fun rootCommandMustCompleteSuccessfullyWithExactReceipt() {
        val launch = claim.tunLaunch(socket, 10000, source, digest)
        val success = RootHotspotRootAccess({ _, _ -> RootCommandRunner.CompleteResult(0, "tun_sent 1234 42\n") })
        assertEquals(42, success.launchTun(launch)?.identity?.index)
        for ((code, text) in listOf(1 to "tun_sent 1234 42\n", 0 to "tun_unconfirmed\n", 0 to "")) {
            val root = RootHotspotRootAccess({ _, _ -> RootCommandRunner.CompleteResult(code, text) })
            assertNull(root.launchTun(launch))
        }
    }

    @Test fun interruptedLaunchNeverCreatesReceipt() {
        val root = RootHotspotRootAccess({ _, _ -> throw InterruptedException() })
        try {
            assertNull(root.launchTun(claim.tunLaunch(socket, 10000, source, digest)))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
