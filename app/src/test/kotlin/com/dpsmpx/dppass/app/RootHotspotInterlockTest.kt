package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotInterlockTest {
    private fun owner() = RootHotspotOwner(
        RootOwnerIdentity(ProcessHandle.current().pid().toInt(), RootProcessIdentity.currentAppStartTime()),
        UUID.fromString(File("/proc/sys/kernel/random/boot_id").readText().trim()),
    )
    private val session = RootHotspotAdmission.Session(7, 12, RootHotspotAdmission.Mode.VPN)
    private fun run(script: String): Int =
        RootCommandRunner.run(listOf("/bin/sh", "-c", script), 10_000).exitCode

    private fun fixture(test: (File, File, File) -> Unit) {
        if (!File("/bin/sh").canExecute() || run("command -v flock >/dev/null") != 0) return
        val root = Files.createTempDirectory("dppass-interlock").toFile()
        try {
            test(File(root, "shared").apply { mkdir() }, File(root, "zapret"), File(root, "bye"))
        } finally {
            root.deleteRecursively()
        }
    }

    @Test fun claimRefusesActiveAdapterAndAllowsAfterStop() = fixture { shared, zapret, bye ->
        val tx = RootLifecycleTransaction(zapret.path, "first", shared.path, bye.path)
        val claim = RootHotspotClaim(session, shared.path, adapterDirectories = listOf(zapret.path, bye.path), owner = owner())
        assertEquals(0, run(tx.start(":", ":")))
        assertFalse(run(claim.acquire()) == 0)
        assertFalse(File(shared, "hotspot.owner").exists())
        assertEquals(0, run(tx.stop(":")))
        assertEquals(0, run(claim.acquire()))
        assertEquals(0, run(claim.releaseAfter(":")))
    }

    @Test fun claimBlocksBothAdapterStartsBeforePrepareOrCleanup() = fixture { shared, zapret, bye ->
        val claim = RootHotspotClaim(session, shared.path, adapterDirectories = listOf(zapret.path, bye.path), owner = owner())
        val action = File(shared, "action")
        val touch = "touch '" + action.path + "'"
        assertEquals(0, run(claim.acquire()))
        for ((dir, peer) in listOf(zapret to bye, bye to zapret)) {
            val tx = RootLifecycleTransaction(dir.path, "next", shared.path, peer.path)
            assertFalse(run(tx.start(touch, touch, prepare = touch)) == 0)
            assertFalse(action.exists())
            assertFalse(dir.exists())
            assertEquals(0, run(tx.stop(touch)))
            assertFalse(action.exists())
        }
        assertEquals(0, run(claim.releaseAfter(":")))
        assertEquals(0, run(RootLifecycleTransaction(zapret.path, "next", shared.path, bye.path).start(":", touch)))
        assertTrue(action.exists())
    }

    @Test fun incompleteAdapterMetadataBlocksClaimWithoutModification() = fixture { shared, zapret, bye ->
        val claim = RootHotspotClaim(session, shared.path, adapterDirectories = listOf(zapret.path, bye.path), owner = owner())
        assertTrue(bye.mkdir())
        for (name in listOf("generation", "owner.identity", "pid", "pid6", "watch.pid",
            "pid.identity", "pid6.identity", "watch.pid.identity", "ipv6.intent", "pidfd.required",
            "generation.next.tmp", "owner.identity.next.tmp")) {
            val file = File(bye, name).apply { writeText("unresolved") }
            assertFalse(run(claim.acquire()) == 0)
            assertEquals("unresolved", file.readText())
            assertTrue(file.delete())
        }
        assertEquals(0, run(claim.acquire()))
    }

    @Test fun ambiguousAdapterPathsAreRejected() = fixture { shared, zapret, bye ->
        val claim = RootHotspotClaim(session, shared.path, adapterDirectories = listOf(zapret.path, bye.path), owner = owner())
        zapret.writeText("not a directory")
        assertFalse(run(claim.acquire()) == 0)
        assertTrue(zapret.delete())
        Files.createSymbolicLink(zapret.toPath(), bye.toPath())
        try {
            assertFalse(run(claim.acquire()) == 0)
        } finally {
            Files.delete(zapret.toPath())
        }
        assertTrue(bye.mkdir())
        val pid = File(bye, "pid")
        Files.createSymbolicLink(pid.toPath(), File(bye, "missing").toPath())
        try {
            assertFalse(run(claim.acquire()) == 0)
        } finally {
            Files.delete(pid.toPath())
        }
    }

    @Test fun malformedOrDanglingClaimStillBlocksAdapterAdmission() = fixture { shared, zapret, bye ->
        val tx = RootLifecycleTransaction(zapret.path, "next", shared.path, bye.path)
        val marker = File(shared, "hotspot.owner")
        marker.writeText("")
        assertFalse(run(tx.start(":", ":")) == 0)
        assertFalse(zapret.exists())
        assertTrue(marker.delete())
        Files.createSymbolicLink(marker.toPath(), File(shared, "missing").toPath())
        try {
            assertFalse(run(tx.start(":", ":")) == 0)
            assertFalse(zapret.exists())
        } finally {
            Files.delete(marker.toPath())
        }
    }

    @Test fun conflictingCleanupDoesNotRunWhileClaimExists() = fixture { shared, zapret, bye ->
        val tx = RootLifecycleTransaction(zapret.path, "first", shared.path, bye.path)
        val action = File(shared, "action")
        val touch = "touch '" + action.path + "'"
        assertEquals(0, run(tx.start(":", ":")))
        // Simulate conflicting metadata from an older noncooperating writer.
        val marker = File(shared, "hotspot.owner").apply { writeText("unresolved") }
        assertFalse(run(tx.stop(touch)) == 0)
        assertFalse(action.exists())
        assertTrue(File(zapret, "generation").exists())
        assertTrue(marker.delete())
        assertEquals(0, run(tx.stop(touch)))
        assertTrue(action.exists())
    }
}
