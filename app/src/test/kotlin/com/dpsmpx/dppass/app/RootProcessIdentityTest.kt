package com.dpsmpx.dppass.app

import java.nio.file.Files
import java.io.File
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
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
            val optional = dir.resolve("optional.pid").toFile()
            val startTime = requireNotNull(RootProcessIdentity.startTime(File("/proc/$pid/stat").readText()))
            fun watchdogStatus(expected: String, appStart: String = startTime): Int = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.watchdogCondition(
                    pid.toInt(), appStart, pidFile.toString(), expected, optional.path,
                )), timeoutMillis = 5_000,
            ).exitCode
            try {
                assertEquals(0, watchdogStatus(executable))
                assertFalse(watchdogStatus(executable, (startTime.toLong() + 1).toString()) == 0)
                assertFalse(watchdogStatus(executable + "-unrelated") == 0)
                optional.writeText("")
                assertFalse(watchdogStatus(executable) == 0)
                optional.writeText("1")
                assertFalse(watchdogStatus(executable) == 0)
                optional.writeText(pid.toString())
                assertEquals(0, watchdogStatus(executable))
            } finally {
                optional.delete()
            }
            for (invalid in listOf("", "0", "1", "-1", "abc", "123 456")) {
                pidFile.toFile().writeText(invalid)
                assertFalse(status(executable) == 0)
            }
            pidFile.toFile().writeText(pid.toString())
            child.destroyForcibly().waitFor()
            assertFalse(status(executable) == 0)
            assertFalse(watchdogStatus(executable) == 0)
        } finally {
            child.destroyForcibly()
            Files.deleteIfExists(pidFile)
            Files.deleteIfExists(dir)
        }
    }

    @Test fun statStartTimeHandlesCommandNamesAndMalformedFields() {
        val fields = (listOf("S") + List(18) { "0" }).joinToString(" ")
        assertEquals("98765", RootProcessIdentity.startTime("123 (a ) tricky name) $fields 98765 0"))
        assertNull(RootProcessIdentity.startTime("123 (name) S 1"))
        assertNull(RootProcessIdentity.startTime("123 (name) $fields -1"))
        assertNull(RootProcessIdentity.startTime("123 (name) $fields nope"))
        assertNull(RootProcessIdentity.startTime("no delimiter"))
    }


    @Test fun lockedTransactionSerializesAndFencesDeferredCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-root-lock")
        val lock = dir.resolve("lifecycle.lock").toString()
        val generation = dir.resolve("generation").toFile()
        val ready = dir.resolve("ready").toFile()
        val release = dir.resolve("release").toFile()
        val marker = dir.resolve("cleanup").toFile()
        generation.writeText("old")
        val holder = ProcessBuilder("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(
            lock, "echo ready > '${ready.path}'; while ! test -e '${release.path}'; do sleep 0.05; done; echo new > '${generation.path}'",
        )).start()
        try {
            val deadline = System.nanoTime() + 3_000_000_000L
            while (!ready.exists() && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(ready.exists())
            val blocked = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(lock, "echo bad > '${marker.path}'", 1)),
                timeoutMillis = 5_000,
            )
            assertFalse(blocked.exitCode == 0)
            assertFalse(marker.exists())
            release.writeText("release")
            assertTrue(holder.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
            assertEquals(0, holder.exitValue())
            fun guarded(expected: String): Int = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(
                    lock, RootProcessIdentity.generationMatches(generation.path, expected) + " || exit 0\n echo cleaned > '${marker.path}'",
                )), timeoutMillis = 5_000,
            ).exitCode
            assertEquals(0, guarded("old"))
            assertFalse(marker.exists())
            assertEquals(0, guarded("new"))
            assertTrue(marker.exists())
            assertTrue(File(lock).exists())
        } finally {
            release.writeText("release")
            if (!holder.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) holder.destroyForcibly().waitFor()
            dir.toFile().deleteRecursively()
        }
    }


    @Test fun detachedChildDoesNotRetainLifecycleLock() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-root-child")
        val lock = dir.resolve("lifecycle.lock").toString()
        val ready = dir.resolve("ready").toFile()
        val release = dir.resolve("release").toFile()
        val done = dir.resolve("done").toFile()
        val child = dir.resolve("child.sh").toFile()
        val log = dir.resolve("child.log").toFile()
        child.writeText(
            "echo ready > '${ready.path}'\n" +
                "i=0; while ! test -e '${release.path}' && test \"\$i\" -lt 200; do " +
                "sleep 0.05; i=\$((i+1)); done\n" +
                "echo done > '${done.path}'\n",
        )
        try {
            val launch = RootProcessIdentity.detachedCommand("sh '${child.path}'", log.path)
            val result = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(lock, launch)),
                timeoutMillis = 5_000,
            )
            assertEquals(0, result.exitCode)
            val deadline = System.nanoTime() + 3_000_000_000L
            while (!ready.exists() && System.nanoTime() < deadline) Thread.sleep(10)
            assertTrue(ready.exists())
            assertFalse(done.exists())
            val second = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(lock, ":", 1)),
                timeoutMillis = 5_000,
            )
            assertEquals(0, second.exitCode)
            assertFalse(done.exists())
        } finally {
            release.writeText("release")
            val deadline = System.nanoTime() + 2_000_000_000L
            while (ready.exists() && !done.exists() && System.nanoTime() < deadline) Thread.sleep(10)
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun lockAndGenerationGuardRejectInvalidInputs() {
        val invalidTimeout = runCatching { RootProcessIdentity.lockedTransaction("/tmp/lock", ":", 0) }
        assertTrue(invalidTimeout.isFailure)
        assertTrue(runCatching { RootProcessIdentity.generationMatches("/tmp/gen", "") }.isFailure)
        assertTrue(runCatching { RootProcessIdentity.generationMatches("/tmp/gen", "bad token") }.isFailure)
        val command = RootProcessIdentity.lockedTransaction("/tmp/lock", "echo action")
        assertTrue(command.indexOf("flock -x -w") < command.indexOf("echo action"))
        assertFalse(command.contains("rm -f"))
    }
}
