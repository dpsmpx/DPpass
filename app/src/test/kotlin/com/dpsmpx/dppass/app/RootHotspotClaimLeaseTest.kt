package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class RootHotspotClaimLeaseTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val slot = RootHotspotNetworkFixture.slot
    private class Resource
    private fun reservation() = RootHotspotReservation<Resource> { }

    private fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c",
        RootHotspotNetworkFixture.clean + script), 10_000).exitCode == 0

    private fun fixture(test: (File, RootHotspotClaim) -> Unit) {
        if (!File("/bin/sh").canExecute() || !run("command -v flock >/dev/null")) return
        val dir = Files.createTempDirectory("dppass-claim-lease").toFile()
        try {
            val owner = RootHotspotOwner(
                RootOwnerIdentity(ProcessHandle.current().pid().toInt(), RootProcessIdentity.currentAppStartTime()),
                UUID.fromString(File("/proc/sys/kernel/random/boot_id").readText().trim()),
            )
            test(dir, RootHotspotClaim.pending(session.generation, session.mode, owner, slot,
                dir.path, adapterDirectories = emptyList()))
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun reserveBeforeDispatchAndBindBeforeOwnedWork() = fixture { dir, claim ->
        val lease = RootHotspotClaimLease<Resource>(claim, ::run)
        val marker = File(dir, "hotspot.owner")
        val resource = Resource()
        val pending = reservation()
        assertTrue(lease.reserveAndRequest(pending) {
            assertTrue(marker.exists())
            assertEquals(null, RootHotspotOwnerRecord.parse(marker.readText())?.session)
            it.started(resource)
        })
        assertEquals(resource, pending.take(1000))
        assertThrows(IllegalStateException::class.java) { lease.owned(":") }
        assertTrue(lease.bind(identity))
        assertTrue(lease.owned(":"))
        assertFalse(lease.retire({ false }, ":"))
        assertTrue(marker.exists())
        assertTrue(lease.retire({ true }, ":"))
        assertFalse(marker.exists())
        assertEquals(RootHotspotClaimLease.State.RETIRED, lease.state)
    }

    @Test fun failedAcquisitionNeverDispatchesOrAllowsSecondAttempt() = fixture { dir, claim ->
        val lease = RootHotspotClaimLease<Resource>(claim) { false }
        assertFalse(lease.reserveAndRequest(reservation()) { error("unexpected dispatch") })
        assertEquals(RootHotspotClaimLease.State.UNCONFIRMED, lease.state)
        assertThrows(IllegalStateException::class.java) {
            lease.reserveAndRequest(reservation()) { error("unexpected dispatch") }
        }
        assertFalse(lease.retire({ true }, ":"))
        assertFalse(File(dir, "hotspot.owner").exists())
    }

    @Test fun dispatchExceptionRetainsClaimUntilIndependentShutdownProof() = fixture { dir, claim ->
        val lease = RootHotspotClaimLease<Resource>(claim, ::run)
        assertThrows(IllegalStateException::class.java) {
            lease.reserveAndRequest(reservation()) { error("platform failure") }
        }
        assertFalse(lease.retire({ false }, ":"))
        assertTrue(File(dir, "hotspot.owner").exists())
        assertTrue(lease.retire({ true }, "false"))
    }

    @Test fun lostBindResponseReconcilesExactBoundClaimWithoutEnablingWork() = fixture { dir, claim ->
        var lose = false
        val lease = RootHotspotClaimLease<Resource>(claim) { script ->
            val ok = run(script)
            if (lose) { lose = false; false } else ok
        }
        assertTrue(lease.reserveAndRequest(reservation()) { })
        lose = true
        assertFalse(lease.bind(identity))
        assertEquals(RootHotspotClaimLease.State.UNCONFIRMED, lease.state)
        assertThrows(IllegalStateException::class.java) { lease.owned(":") }
        assertEquals(session, RootHotspotOwnerRecord.parse(File(dir, "hotspot.owner").readText())?.session)
        assertFalse(lease.retire({ true }, "false"))
        assertTrue(lease.retire({ true }, ":"))
    }

    @Test fun failedBindKeepsPendingClaimAndSkipsBoundCleanup() = fixture { dir, claim ->
        var fail = false
        val lease = RootHotspotClaimLease<Resource>(claim) { script ->
            if (fail) { fail = false; false } else run(script)
        }
        assertTrue(lease.reserveAndRequest(reservation()) { })
        fail = true
        assertFalse(lease.bind(identity))
        assertEquals(null, RootHotspotOwnerRecord.parse(File(dir, "hotspot.owner").readText())?.session)
        assertTrue(lease.retire({ true }, "false"))
        assertFalse(File(dir, "hotspot.owner").exists())
    }

    @Test fun failedReleaseCanRetryButDoesNotAdmitFreshRequest() = fixture { dir, claim ->
        val lease = RootHotspotClaimLease<Resource>(claim, ::run)
        assertTrue(lease.reserveAndRequest(reservation()) { })
        assertTrue(lease.bind(identity))
        assertFalse(lease.retire({ true }, "false"))
        assertTrue(File(dir, "hotspot.owner").exists())
        assertThrows(IllegalStateException::class.java) {
            lease.reserveAndRequest(reservation()) { }
        }
        assertTrue(lease.retire({ true }, ":"))
        assertTrue(lease.retire({ error("already retired") }, "false"))
    }
}
