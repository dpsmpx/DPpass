package com.dpsmpx.dppass.app

import java.nio.file.Files
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
        val child = ProcessBuilder("/bin/sh", "-c", "echo \$\$; exec \"\$1\" 15", "identity-test", sleep).start()
        val dir = Files.createTempDirectory("dppass-root-identity")
        val pidFile = dir.resolve("daemon.pid")
        try {
            val pid = child.inputStream.bufferedReader().readLine().toLong()
            val executable = File(sleep).canonicalPath
            // The shell prints its PID immediately before exec. Wait for
            // the same process to acquire the expected executable identity.
            val link = File("/proc/$pid/exe")
            val deadline = System.nanoTime() + 2_000_000_000L
            while (link.canonicalPath != executable && System.nanoTime() < deadline) {
                Thread.sleep(10)
            }
            assertEquals(executable, link.canonicalPath)
            fun status(expected: String): Int = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.executableAlive(pidFile.toString(), expected)),
                timeoutMillis = 5_000,
            ).exitCode
            assertFalse(status(executable) == 0)
            pidFile.toFile().writeText(pid.toString())
            assertEquals(0, status(executable))
            assertFalse(status(executable + "-unrelated") == 0)
            for (invalid in listOf("", "0", "1", "-1", "abc", "123 456")) {
                pidFile.toFile().writeText(invalid)
                assertFalse(status(executable) == 0)
            }
            pidFile.toFile().writeText(pid.toString())
            child.destroyForcibly().waitFor()
            assertFalse(status(executable) == 0)
        } finally {
            child.destroyForcibly()
            Files.deleteIfExists(pidFile)
            Files.deleteIfExists(dir)
        }
    }

}
