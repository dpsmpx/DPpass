package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotRecoveryTest {
    private val session = RootHotspotAdmission.Session(7, 12, RootHotspotAdmission.Mode.VPN)
    private val boot = UUID.fromString("11111111-2222-3333-4444-555555555555")
    private val otherBoot = UUID.fromString("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")
    private val token = UUID.fromString("12345678-1234-1234-1234-123456789abc")
    private val owner = RootHotspotOwner(RootOwnerIdentity(123, "456"), boot)
    private val record = RootHotspotOwnerRecord(session, token, owner)
    private fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c", script), 10_000).exitCode

    @Test fun recordIsCanonicalAndBounded() {
        val raw = record.line() + "\n"
        assertEquals(record, RootHotspotOwnerRecord.parse(raw))
        for (bad in listOf(raw.trimEnd(), raw + "\n", raw.replace("v2", "v1"),
            raw.replace(" 7 ", " 07 "), raw.replace(" 123 ", " 1 "), raw.replace(" 456 ", " 0456 "),
            raw.replace("VPN", "UNKNOWN"), raw.replace(token.toString(), "1-1-1-1-1"),
            raw.replace(boot.toString(), boot.toString().uppercase().replace("1", "A") + "x"),
            "x".repeat(257))) {
            assertNull(RootHotspotOwnerRecord.parse(bad))
        }
    }

    private fun fixture(test: (File, File, File, RootHotspotClaim) -> Unit) {
        if (!File("/bin/sh").canExecute() || run("command -v flock >/dev/null") != 0) return
        val dir = Files.createTempDirectory("dppass-hotspot-recovery").toFile()
        try {
            val proc = File(dir, "proc").apply { mkdir() }
            val bootFile = File(proc, "sys/kernel/random/boot_id").apply {
                parentFile.mkdirs()
                writeText(otherBoot.toString() + "\n")
            }
            val marker = File(dir, "hotspot.owner").apply { writeText(record.line() + "\n") }
            val claim = RootHotspotClaim(session, dir.path, token, adapterDirectories = emptyList(),
                owner = owner, procRoot = proc.path)
            test(dir, bootFile, marker, claim)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun previousBootStillRequiresVerifiedCleanup() = fixture { _, _, marker, claim ->
        assertFalse(run(claim.releaseAfter(":")) == 0)
        assertFalse(run(claim.recoverAfter("false")) == 0)
        assertTrue(marker.exists())
        assertEquals(0, run(claim.recoverAfter(":")))
        assertFalse(marker.exists())
    }

    @Test fun sameBootMissingProcessOrInvalidBootDoesNotAuthorizeRecovery() = fixture { dir, bootFile, marker, claim ->
        val action = File(dir, "action")
        val touch = "touch '" + action.path + "'"
        for (value in listOf(boot.toString(), "", "invalid")) {
            bootFile.writeText(value + "\n")
            assertFalse(run(claim.recoverAfter(touch)) == 0)
            assertFalse(action.exists())
            assertTrue(marker.exists())
        }
        assertTrue(bootFile.delete())
        assertFalse(run(claim.recoverAfter(touch)) == 0)
    }

    @Test fun staleRecordCannotRecoverNewOwner() = fixture { dir, _, marker, claim ->
        val action = File(dir, "action")
        val changed = record.copy(token = UUID.randomUUID()).line() + "\n"
        marker.writeText(changed)
        assertFalse(run(claim.recoverAfter("touch '" + action.path + "'")) == 0)
        assertFalse(action.exists())
        assertEquals(changed, marker.readText())
    }

    @Test fun inspectionIsReadOnlyAndRejectsOversizedRecord() = fixture { dir, _, marker, _ ->
        val result = RootCommandRunner.runComplete(listOf("/bin/sh", "-c", RootHotspotClaim.inspect(dir.path)))
        assertEquals(0, result.exitCode)
        assertEquals(record, RootHotspotOwnerRecord.parse(result.stdout))
        marker.writeText("x".repeat(257))
        assertFalse(run(RootHotspotClaim.inspect(dir.path)) == 0)
        assertEquals(257, marker.length().toInt())
    }

    @Test fun sameBootRequiresPositiveNativeGoneResult() = fixture { dir, bootFile, marker, claim ->
        bootFile.writeText(boot.toString() + "\n")
        val helper = File(dir, "helper")
        fun install(code: Int) {
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; " +
                "gone) test \"\$2 \$3 \$4\" = '123 456 " + boot + "' || exit 1; exit " + code +
                ";; *) exit 1;; esac\n")
            assertTrue(helper.setExecutable(true, true))
        }
        install(1)
        assertFalse(run(claim.recoverAfter(":", helper.path)) == 0)
        assertTrue(marker.exists())
        install(0)
        assertEquals(0, run(claim.recoverAfter(":", helper.path)))
        assertFalse(marker.exists())
    }
}
