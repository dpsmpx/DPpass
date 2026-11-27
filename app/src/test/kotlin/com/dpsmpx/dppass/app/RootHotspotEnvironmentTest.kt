package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotEnvironmentTest {
    private fun shell(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c", script), 10_000).exitCode
    private fun fixture(block: (File) -> Unit) {
        if (!File("/bin/sh").canExecute() || shell("command -v flock >/dev/null") != 0) return
        val dir = Files.createTempDirectory("dppass-hotspot-environment").toFile()
        try { block(dir) } finally { dir.deleteRecursively() }
    }

    @Test fun initializesPrivateDirectoryAndPreservesExistingLockAndRecord() = fixture { parent ->
        val dir = File(parent, "root")
        assertEquals(0, shell(RootHotspotEnvironment.initialize(dir.path)))
        val lock = File(dir, "lifecycle.lock")
        val inode = Files.getAttribute(lock.toPath(), "unix:ino")
        val marker = File(dir, "hotspot.owner")
        marker.writeText("unresolved\n")
        assertEquals(0, shell(RootHotspotEnvironment.initialize(dir.path)))
        assertEquals(inode, Files.getAttribute(lock.toPath(), "unix:ino"))
        assertEquals("unresolved\n", marker.readText())
    }

    @Test fun refusesNonprivateDirectoryAndSymlinksWithoutChangingThem() = fixture { parent ->
        val target = File(parent, "target").apply { mkdir() }
        assertEquals(0, shell("chmod 755 '" + target.path + "'"))
        assertFalse(shell(RootHotspotEnvironment.initialize(target.path)) == 0)
        assertFalse(File(target, "lifecycle.lock").exists())
        val link = File(parent, "link")
        Files.createSymbolicLink(link.toPath(), target.toPath())
        assertFalse(shell(RootHotspotEnvironment.initialize(link.path)) == 0)
        assertTrue(Files.isSymbolicLink(link.toPath()))
        val file = File(parent, "regular").apply { writeText("keep") }
        assertFalse(shell(RootHotspotEnvironment.initialize(file.path)) == 0)
        assertEquals("keep", file.readText())
    }

    @Test fun missingParentIsNotCreatedRecursively() = fixture { parent ->
        val missing = File(parent, "missing")
        assertFalse(shell(RootHotspotEnvironment.initialize(File(missing, "root").path)) == 0)
        assertFalse(missing.exists())
    }

    @Test fun initializationDoesNotInterpretExtraOutputAsSuccess() {
        for ((code, output) in listOf(0 to "", 1 to "environment_ready\n", 0 to "environment_ready\nextra")) {
            assertFalse(RootHotspotRootAccess({ _, _ ->
                RootCommandRunner.CompleteResult(code, output)
            }).initialize())
        }
        assertTrue(RootHotspotRootAccess({ _, _ ->
            RootCommandRunner.CompleteResult(0, "environment_ready\n")
        }).initialize())
    }
}
