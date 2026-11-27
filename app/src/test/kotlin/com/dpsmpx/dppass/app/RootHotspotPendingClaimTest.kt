package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotPendingClaimTest {
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val slot = RootHotspotNetworkFixture.slot

    private fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c",
        RootHotspotNetworkFixture.clean + script), 10_000).exitCode

    private fun fixture(test: (File, RootHotspotClaim) -> Unit) {
        if (!File("/bin/sh").canExecute() || run("command -v flock >/dev/null") != 0) return
        val dir = Files.createTempDirectory("dppass-pending-hotspot").toFile()
        try {
            val owner = RootHotspotOwner(
                RootOwnerIdentity(ProcessHandle.current().pid().toInt(), RootProcessIdentity.currentAppStartTime()),
                UUID.fromString(File("/proc/sys/kernel/random/boot_id").readText().trim()),
            )
            val claim = RootHotspotClaim.pending(session.generation, session.mode, owner, slot,
                dir.path, adapterDirectories = emptyList())
            test(dir, claim)
        } finally {
            dir.deleteRecursively()
        }
    }

    private fun read(dir: File) = requireNotNull(RootHotspotOwnerRecord.parse(File(dir, "hotspot.owner").readText()))

    @Test fun pendingClaimBlocksRootAdapterBeforeApExists() = fixture { dir, claim ->
        val adapter = File(dir, "adapter")
        val tx = RootLifecycleTransaction(adapter.path, "next", dir.path, File(dir, "peer").path)
        assertEquals(0, run(claim.acquire()))
        assertNull(read(dir).session)
        assertFalse(run(tx.start(":", ":")) == 0)
        assertFalse(adapter.exists())
        assertFalse(runCatching { claim.owned(":") }.isSuccess)
    }

    @Test fun bindPreservesTokenOwnerAndSlotAndInvalidatesPendingHandle() = fixture { dir, claim ->
        assertEquals(0, run(claim.acquire()))
        val before = read(dir)
        val binding = claim.bind(session)
        assertEquals(0, run(binding.script))
        val after = read(dir)
        assertEquals(before.copy(downstreamIndex = session.downstreamIndex), after)
        assertEquals(session, after.session)
        assertFalse(run(claim.releaseAfter(":")) == 0)
        assertFalse(run(binding.script) == 0)
        assertEquals(0, run(binding.claim.owned(":")))
        assertEquals(0, run(binding.claim.releaseAfter(":")))
    }

    @Test fun wrongSessionOrSecondBindCannotChangeOwnership() = fixture { dir, claim ->
        assertEquals(0, run(claim.acquire()))
        val before = read(dir)
        assertFalse(runCatching { claim.bind(session.copy(generation = 10)) }.isSuccess)
        assertFalse(runCatching { claim.bind(session.copy(mode = RootHotspotAdmission.Mode.LOCAL_STRATEGIES)) }.isSuccess)
        assertEquals(before, read(dir))
        val bound = claim.bind(session)
        assertEquals(0, run(bound.script))
        assertFalse(runCatching { bound.claim.bind(session) }.isSuccess)
    }

    @Test fun ambiguousBindKeepsOriginalRecordAndAllowsInspection() = fixture { dir, claim ->
        assertEquals(0, run(claim.acquire()))
        val before = read(dir)
        val failMove = "mv() { return 1; }\n"
        assertFalse(run(failMove + claim.bind(session).script) == 0)
        assertEquals(before, read(dir))
        assertEquals(0, run(claim.bind(session).script))
        assertEquals(session, read(dir).session)
    }

    @Test fun pendingReleaseRequiresCleanupAndReconstructionIsExact() = fixture { dir, claim ->
        assertEquals(0, run(claim.acquire()))
        val record = read(dir)
        val reconstructed = RootHotspotClaim.fromRecord(record, dir.path, adapterDirectories = emptyList())
        assertFalse(run(reconstructed.releaseAfter("false")) == 0)
        assertEquals(record, read(dir))
        assertEquals(0, run(reconstructed.releaseAfter(":")))
        assertFalse(File(dir, "hotspot.owner").exists())
    }

    @Test fun pendingRecordRejectsNegativeOrNoncanonicalIndex() = fixture { dir, claim ->
        assertEquals(0, run(claim.acquire()))
        val raw = read(dir).line() + "\n"
        assertNull(RootHotspotOwnerRecord.parse(raw.replace(" 9 0 ", " 9 -1 ")))
        assertNull(RootHotspotOwnerRecord.parse(raw.replace(" 9 0 ", " 9 00 ")))
        assertTrue(read(dir).downstreamIndex == null)
    }
}
