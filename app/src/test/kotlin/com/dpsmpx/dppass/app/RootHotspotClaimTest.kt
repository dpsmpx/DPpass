package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotClaimTest {
    private fun owner() = RootHotspotOwner(
        RootOwnerIdentity(ProcessHandle.current().pid().toInt(), RootProcessIdentity.currentAppStartTime()),
        UUID.fromString(File("/proc/sys/kernel/random/boot_id").readText().trim()),
    )
    private val session = RootHotspotAdmission.Session(7, 12, RootHotspotAdmission.Mode.VPN)

    private fun run(script: String): Int =
        RootCommandRunner.run(listOf("/bin/sh", "-c", RootHotspotNetworkFixture.clean + script), 10_000).exitCode

    private fun fixture(test: (File) -> Unit) {
        if (!File("/bin/sh").canExecute() || run("command -v flock >/dev/null") != 0) return
        val dir = Files.createTempDirectory("dppass-hotspot-claim").toFile()
        try {
            test(dir)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun claimSurvivesCommandExitAndRejectsAnotherOwner() = fixture { dir ->
        val first = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val second = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        assertEquals(0, run(first.acquire()))
        val marker = File(dir, "hotspot.owner")
        val record = marker.readText()
        assertFalse(run(second.acquire()) == 0)
        assertFalse(run(first.acquire()) == 0)
        assertEquals(record, marker.readText())
        assertEquals(0, run(first.releaseAfter(":")))
        assertFalse(marker.exists())
        assertEquals(0, run(second.acquire()))
        assertEquals(0, run(second.releaseAfter(":")))
        assertTrue(File(dir, "lifecycle.lock").isFile)
    }

    @Test fun staleOwnerCannotExecuteOrReleaseNewClaim() = fixture { dir ->
        val first = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val second = RootHotspotClaim(session.copy(generation = 8), dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val action = File(dir, "action")
        val touch = "touch '" + action.path + "'"
        assertEquals(0, run(first.acquire()))
        assertEquals(0, run(first.releaseAfter(":")))
        assertEquals(0, run(second.acquire()))
        assertFalse(run(first.owned(touch)) == 0)
        assertFalse(run(first.releaseAfter(touch)) == 0)
        assertFalse(action.exists())
        assertEquals(0, run(second.owned(touch)))
        assertTrue(action.exists())
    }

    @Test fun failedCleanupRetainsClaimAndCanBeRetried() = fixture { dir ->
        val claim = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        assertEquals(0, run(claim.acquire()))
        val marker = File(dir, "hotspot.owner")
        val record = marker.readText()
        assertFalse(run(claim.releaseAfter("false")) == 0)
        assertEquals(record, marker.readText())
        assertFalse(run(RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot).acquire()) == 0)
        assertEquals(0, run(claim.releaseAfter(":")))
    }

    @Test fun malformedRecordAndDifferentSessionFailClosed() = fixture { dir ->
        val token = UUID.randomUUID()
        val claim = RootHotspotClaim(session, dir.path, token, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val marker = File(dir, "hotspot.owner")
        assertEquals(0, run(claim.acquire()))
        val valid = marker.readText()
        val wrong = RootHotspotClaim(session.copy(downstreamIndex = 13), dir.path, token, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        assertFalse(run(wrong.owned(":")) == 0)
        assertFalse(run(wrong.releaseAfter(":")) == 0)
        for (bad in listOf("", valid.trimEnd(), valid + "\n", valid.replace("v3", "v2"))) {
            marker.writeText(bad)
            assertFalse(run(claim.owned(":")) == 0)
            assertFalse(run(claim.releaseAfter(":")) == 0)
            assertFalse(run(claim.acquire()) == 0)
            assertEquals(bad, marker.readText())
        }
    }

    @Test fun nonregularAndSymlinkClaimsAreNotFollowed() = fixture { dir ->
        val marker = File(dir, "hotspot.owner")
        val target = File(dir, "outside").apply { writeText("unchanged") }
        val claim = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        Files.createSymbolicLink(marker.toPath(), target.toPath())
        try {
            assertFalse(run(claim.acquire()) == 0)
            assertFalse(run(claim.releaseAfter(":")) == 0)
            assertEquals("unchanged", target.readText())
        } finally {
            Files.delete(marker.toPath())
        }
        assertTrue(marker.mkdir())
        assertFalse(run(claim.acquire()) == 0)
        assertFalse(run(claim.releaseAfter(":")) == 0)
        assertTrue(marker.isDirectory)
    }

    @Test fun dirtyNetworkPreventsClaimAndRetirementEvenWithSuccessfulCallback() = fixture { dir ->
        val claim = RootHotspotClaim(session, dir.path, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val marker = File(dir, "hotspot.owner")
        assertFalse(run(RootHotspotNetworkFixture.dirty + claim.acquire()) == 0)
        assertFalse(marker.exists())
        assertEquals(0, run(claim.acquire()))
        val record = marker.readText()
        assertFalse(run(RootHotspotNetworkFixture.dirty + claim.releaseAfter(":")) == 0)
        assertEquals(record, marker.readText())
        assertEquals(0, run(claim.releaseAfter(":")))
    }

    @Test fun wrongNetworkSlotCannotOperateOnExactToken() = fixture { dir ->
        val token = UUID.randomUUID()
        val owner = owner()
        val claim = RootHotspotClaim(session, dir.path, token, owner = owner, networkSlot = RootHotspotNetworkFixture.slot)
        val wrong = RootHotspotClaim(session, dir.path, token, owner = owner, networkSlot = RootHotspotNetworkSlot(12001, 401))
        assertEquals(0, run(claim.acquire()))
        assertFalse(run(wrong.owned(":")) == 0)
        assertFalse(run(wrong.releaseAfter(":")) == 0)
        assertEquals(0, run(claim.releaseAfter(":")))
    }

    @Test fun lockContentionCannotCreateClaim() = fixture { dir ->
        val claim = RootHotspotClaim(session, dir.path, waitSeconds = 1, owner = owner(), networkSlot = RootHotspotNetworkFixture.slot)
        val lock = File(dir, "lifecycle.lock")
        val holder = ProcessBuilder("/bin/sh", "-c",
            "exec 9>>\"\$1\"; flock -x 9 || exit 1; echo ready; read line", "fixture", lock.path)
            .redirectErrorStream(true).start()
        try {
            assertEquals("ready", holder.inputStream.bufferedReader().readLine())
            assertFalse(run(claim.acquire()) == 0)
            assertFalse(File(dir, "hotspot.owner").exists())
        } finally {
            holder.outputStream.close()
            holder.destroyForcibly().waitFor()
        }
        assertEquals(0, run(claim.acquire()))
        assertEquals(0, run(claim.releaseAfter(":")))
    }
}
