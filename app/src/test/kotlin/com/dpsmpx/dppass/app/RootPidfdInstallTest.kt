package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import java.security.MessageDigest
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootPidfdInstallTest {
    @Test fun verifiedPublicationRetainsOldHelperOnInvalidInput() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-pidfd-install").toFile()
        val source = File(dir, "source")
        val target = File(dir, "root-pidfd")
        val first = "#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; probe) echo supported;; *) exit 1;; esac\n"
        fun digest(data: String) = MessageDigest.getInstance("SHA-256").digest(data.toByteArray())
            .joinToString("") { "%02x".format(it) }
        fun run(hash: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", RootPidfdInstall.script(dir.path, source.path, hash)),
            timeoutMillis = 5000,
        )
        try {
            source.writeText(first)
            assertEquals(0, run(digest(first)).exitCode)
            assertEquals(first, target.readText())
            assertTrue(target.canExecute())
            source.writeText("invalid")
            assertFalse(run(digest(first)).exitCode == 0)
            assertEquals(first, target.readText())
            assertFalse(run(digest("invalid")).exitCode == 0)
            assertEquals(first, target.readText())
            assertTrue(target.delete())
            val outside = File(dir, "outside").apply { writeText("unchanged") }
            Files.createSymbolicLink(target.toPath(), outside.toPath())
            source.writeText(first)
            assertFalse(run(digest(first)).exitCode == 0)
            assertEquals("unchanged", outside.readText())
            assertTrue(dir.listFiles().orEmpty().none { it.name.startsWith(".root-pidfd.") })
        } finally {
            dir.deleteRecursively()
        }
    }
}
