package com.dpsmpx.dppass.app

import java.nio.file.Files
import java.nio.file.Path
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootProcessIdentityTest {
    @Test fun executableCleanupChecksNumericPidAndExactPath() {
        val command = RootProcessIdentity.stopExecutable("/root/pid", "/root/daemon")
        assertTrue(command.contains("[!0-9]"))
        assertTrue(command.contains("-gt 1"))
        assertTrue(command.contains("readlink /proc/"))
        assertTrue(command.contains("= '/root/daemon'"))
        assertTrue(command.indexOf("readlink") < command.indexOf("kill "))
        assertTrue(command.endsWith("rm -f '/root/pid'"))
        assertFalse(command.contains("kill -9"))
    }

    @Test fun scriptCleanupUsesExactArgumentRatherThanSubstring() {
        val command = RootProcessIdentity.stopScript("/root/watch.pid", "/root/watch.sh")
        assertTrue(command.contains("[!0-9]"))
        assertTrue(command.contains("-gt 1"))
        assertTrue(command.contains("grep -Fxq '/root/watch.sh'"))
        assertTrue(command.indexOf("grep -Fxq") < command.indexOf("kill "))
        assertTrue(command.endsWith("rm -f '/root/watch.pid'"))
    }
    @Test fun executableAliveRejectsUnrelatedOrInvalidPid() {
        if (!File("/bin/sh").canExecute() || !File("/proc/self/exe").exists()) return
        val sleep = listOf("/bin/sleep", "/usr/bin/sleep").firstOrNull { File(it).canExecute() } ?: return
        val child = ProcessBuilder(sleep, "15").start()
        val dir = Files.createTempDirectory("dppass-root-identity")
        val pidFile = dir.resolve("daemon.pid")
        try {
            val executable = Path.of("/proc", child.pid().toString(), "exe").toRealPath().toString()
            fun status(expected: String): Int = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.executableAlive(pidFile.toString(), expected)),
                timeoutMillis = 5_000,
            ).exitCode
            assertFalse(status(executable) == 0)
            Files.writeString(pidFile, child.pid().toString())
            assertEquals(0, status(executable))
            assertFalse(status(executable + "-unrelated") == 0)
            for (invalid in listOf("", "0", "1", "-1", "abc", "123 456")) {
                Files.writeString(pidFile, invalid)
                assertFalse(status(executable) == 0)
            }
            Files.writeString(pidFile, child.pid().toString())
            child.destroyForcibly().waitFor()
            assertFalse(status(executable) == 0)
        } finally {
            child.destroyForcibly()
            Files.deleteIfExists(pidFile)
            Files.deleteIfExists(dir)
        }
    }

}
