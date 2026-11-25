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
        assertTrue(command.endsWith("rm -f '/root/pid' || exit 1"))
        assertFalse(command.contains("kill -9"))
    }

    @Test fun scriptCleanupUsesExactArgumentRatherThanSubstring() {
        val command = RootProcessIdentity.stopScript("/root/watch.pid", "/root/watch.sh")
        assertTrue(command.contains("[!0-9]"))
        assertTrue(command.contains("-gt 1"))
        assertTrue(command.contains("grep -Fxq '/root/watch.sh'"))
        assertTrue(command.indexOf("grep -Fxq") < command.indexOf("kill "))
        assertTrue(command.endsWith("rm -f '/root/watch.pid' || exit 1"))
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

    @Test fun failedSignalRetainsPidAndSuccessfulRetryRemovesIt() {
        if (!File("/bin/sh").canExecute() || !File("/proc/self/exe").exists()) return
        val sleep = listOf("/bin/sleep", "/usr/bin/sleep").firstOrNull { File(it).canExecute() } ?: return
        val child = ProcessBuilder("/bin/sh", "-c", "echo \$\$; exec \"\$1\" 15", "identity-test", sleep).start()
        val dir = Files.createTempDirectory("dppass-root-stop")
        val pidFile = dir.resolve("daemon.pid").toFile()
        try {
            val pid = child.inputStream.bufferedReader().readLine().toLong()
            val executable = File(sleep).canonicalPath
            val link = File("/proc/$pid/exe")
            val deadline = System.nanoTime() + 2_000_000_000L
            while (link.canonicalPath != executable && System.nanoTime() < deadline) Thread.sleep(10)
            assertEquals(executable, link.canonicalPath)
            pidFile.writeText(pid.toString())
            val command = RootProcessIdentity.stopExecutable(pidFile.path, executable)
            fun run(script: String) = RootCommandRunner.run(
                listOf("/bin/sh", "-c", script), timeoutMillis = 5_000,
            )
            val failure = run("kill() { return 1; }\n" + command)
            assertFalse(failure.exitCode == 0)
            assertTrue(failure.outputTail.contains("ROOT: process stop failed"))
            assertTrue(child.isAlive)
            assertEquals(pid.toString(), pidFile.readText())
            val noExit = run("kill() { return 0; }\n" + command)
            assertFalse(noExit.exitCode == 0)
            assertTrue(noExit.outputTail.contains("ROOT: process still active"))
            assertTrue(child.isAlive)
            assertTrue(pidFile.exists())
            val stopped = run(command)
            assertEquals(0, stopped.exitCode)
            assertTrue(child.waitFor(2, java.util.concurrent.TimeUnit.SECONDS))
            assertFalse(pidFile.exists())
        } finally {
            child.destroyForcibly().waitFor()
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun mismatchedExecutableNeverSignalsUnrelatedProcess() {
        if (!File("/bin/sh").canExecute() || !File("/proc/self/exe").exists()) return
        val sleep = listOf("/bin/sleep", "/usr/bin/sleep").firstOrNull { File(it).canExecute() } ?: return
        val child = ProcessBuilder("/bin/sh", "-c", "echo \$\$; exec \"\$1\" 15", "identity-test", sleep).start()
        val dir = Files.createTempDirectory("dppass-root-unrelated")
        val pidFile = dir.resolve("daemon.pid").toFile()
        try {
            val pid = child.inputStream.bufferedReader().readLine().toLong()
            pidFile.writeText(pid.toString())
            val result = RootCommandRunner.run(listOf("/bin/sh", "-c",
                "kill() { echo unexpected_signal; exit 42; }\n" +
                    RootProcessIdentity.stopExecutable(pidFile.path, "/not-the-owned-executable"),
            ), timeoutMillis = 5_000)
            assertEquals(0, result.exitCode)
            assertTrue(child.isAlive)
            assertFalse(result.outputTail.contains("unexpected_signal"))
            assertFalse(pidFile.exists())
        } finally {
            child.destroyForcibly().waitFor()
            dir.toFile().deleteRecursively()
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


    @Test fun lockOpenFailureNeverRunsTransactionBody() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-root-lock-failure")
        val marker = dir.resolve("ran").toFile()
        try {
            val result = RootCommandRunner.run(listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(
                dir.resolve("missing-parent").resolve("lock").toString(),
                "echo ran > '${marker.path}'",
            )), timeoutMillis = 5_000)
            assertFalse(result.exitCode == 0)
            assertFalse(marker.exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun failedTransactionReturnsOriginalStatusAndReleasesLock() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-root-lock-status")
        val lock = dir.resolve("lock with space").toString()
        try {
            fun run(body: String) = RootCommandRunner.run(
                listOf("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(lock, body, 1)),
                timeoutMillis = 5_000,
            )
            val failed = run("echo cleanup_failed; exit 7")
            assertEquals(7, failed.exitCode)
            assertTrue(failed.outputTail.contains("cleanup_failed"))
            assertEquals(0, run(":").exitCode)
            assertTrue(File(lock).isFile)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun lifecycleTransactionFencesObsoleteOwnerAndPreservesFailedCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-lifecycle-transaction")
        val first = RootLifecycleTransaction(dir.toString(), "first")
        val second = RootLifecycleTransaction(dir.toString(), "second")
        val record = dir.resolve("generation").toFile()
        val marker = dir.resolve("marker").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            assertEquals(0, run(first.start("exit 0", "echo first > '${marker.path}'")))
            assertEquals("first", record.readText().trim())
            assertEquals(0, run(first.alive(":")))
            assertEquals(0, run(second.start("exit 0", "echo second > '${marker.path}'")))
            assertEquals("second", record.readText().trim())
            assertFalse(run(first.alive(":")) == 0)
            assertEquals(0, run(first.stop("exit 9")))
            assertEquals("second", marker.readText().trim())
            assertFalse(run(second.stop("exit 7")) == 0)
            assertEquals("second", record.readText().trim())
            assertEquals(0, run(second.stop("exit 0")))
            assertFalse(record.exists())
            assertTrue(dir.resolve("lifecycle.lock").toFile().exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun lifecycleStartupDoesNotLaunchAfterFailedInitialCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-lifecycle-start-failure")
        val lifecycle = RootLifecycleTransaction(dir.toString(), "owner")
        val marker = dir.resolve("started").toFile()
        try {
            val result = RootCommandRunner.run(listOf("/bin/sh", "-c",
                lifecycle.start("exit 7", "echo started > '${marker.path}'"),
            ), timeoutMillis = 10_000)
            assertFalse(result.exitCode == 0)
            assertFalse(marker.exists())
            assertEquals("owner", dir.resolve("generation").toFile().readText().trim())
            assertEquals(0, RootCommandRunner.run(listOf("/bin/sh", "-c",
                lifecycle.stop("exit 0"),
            ), timeoutMillis = 10_000).exitCode)
            assertFalse(dir.resolve("generation").toFile().exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun watchdogPollKeepsHealthyOwnerAndRetriesFailedCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-watchdog-poll")
        val lifecycle = RootLifecycleTransaction(dir.toString(), "owner")
        val marker = dir.resolve("cleaned").toFile()
        val record = dir.resolve("generation").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            assertEquals(0, run(lifecycle.start(":", ":")))
            val cleanup = "echo cleaned > '${marker.path}'"
            assertEquals(75, run(lifecycle.watchdogPoll(":", cleanup)))
            assertFalse(marker.exists())
            assertEquals("owner", record.readText().trim())
            assertFalse(run(lifecycle.watchdogPoll("false", "exit 7")) == 0)
            assertEquals("owner", record.readText().trim())
            assertEquals(0, run(lifecycle.watchdogPoll("false", cleanup)))
            assertTrue(marker.exists())
            assertFalse(record.exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun obsoleteWatchdogExitsWithoutEvaluatingHealthOrCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-watchdog-obsolete")
        val old = RootLifecycleTransaction(dir.toString(), "old")
        val current = RootLifecycleTransaction(dir.toString(), "current")
        val marker = dir.resolve("unexpected").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            assertEquals(0, run(current.start(":", ":")))
            assertEquals(0, run(old.watchdog(
                "echo probe > '${marker.path}'; false",
                "echo cleanup > '${marker.path}'",
            )))
            assertFalse(marker.exists())
            assertEquals("current", dir.resolve("generation").toFile().readText().trim())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun sharedLifecycleRejectsPeerUntilCleanupSucceeds() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-shared-lifecycle")
        val shared = dir.resolve("shared").toString()
        val aDir = dir.resolve("a").toString()
        val bDir = dir.resolve("b").toString()
        val a = RootLifecycleTransaction(aDir, "first", shared, bDir)
        val b = RootLifecycleTransaction(bDir, "second", shared, aDir)
        val aRecord = File(aDir, "generation")
        val bRecord = File(bDir, "generation")
        val marker = dir.resolve("unexpected").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            assertEquals(0, run(a.start(":", ":")).exitCode)
            val denied = b.start("echo cleanup > '${marker.path}'", "echo launch > '${marker.path}'")
            val failure = run(denied)
            assertFalse(failure.exitCode == 0)
            assertTrue(failure.outputTail.contains("other adapter cleanup pending or active"))
            assertFalse(marker.exists())
            assertFalse(bRecord.exists())
            assertEquals("first", aRecord.readText().trim())
            assertEquals(0, run(b.stop("exit 7")).exitCode)
            assertFalse(run(a.stop("exit 7")).exitCode == 0)
            assertFalse(run(denied).exitCode == 0)
            assertFalse(marker.exists())
            assertEquals(0, run(a.stop(":")).exitCode)
            assertEquals(0, run(b.start(":", ":")).exitCode)
            assertFalse(aRecord.exists())
            assertEquals("second", bRecord.readText().trim())
            assertTrue(File(shared, "lifecycle.lock").isFile)
            assertFalse(File(aDir, "lifecycle.lock").exists())
            assertFalse(File(bDir, "lifecycle.lock").exists())
            assertEquals(0, run(b.stop(":")).exitCode)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun sharedStartupWaitsForPreviousAdapterLockBeforeReplacingGeneration() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-legacy-lock")
        val adapter = dir.resolve("adapter").toString()
        val shared = dir.resolve("shared").toString()
        val previous = RootLifecycleTransaction(adapter, "previous")
        val next = RootLifecycleTransaction(adapter, "next", shared)
        val record = File(adapter, "generation")
        val lock = File(adapter, "lifecycle.lock")
        val ready = dir.resolve("ready").toFile()
        val release = dir.resolve("release").toFile()
        val marker = dir.resolve("action").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            assertEquals(0, run(previous.start(":", ":")).exitCode)
            val holder = ProcessBuilder("/bin/sh", "-c", RootProcessIdentity.lockedTransaction(
                lock.path,
                "echo ready > '${ready.path}'; i=0; while ! test -e '${release.path}' && test \"\$i\" -lt 200; do " +
                    "sleep 0.05; i=\$((i+1)); done",
            )).start()
            try {
                val deadline = System.nanoTime() + 3_000_000_000L
                while (!ready.exists() && System.nanoTime() < deadline) Thread.sleep(10)
                assertTrue(ready.exists())
                val startup = next.start("echo cleanup > '${marker.path}'", "echo launch > '${marker.path}'")
                assertFalse(run(startup).exitCode == 0)
                assertFalse(marker.exists())
                assertEquals("previous", record.readText().trim())
                release.writeText("release")
                assertTrue(holder.waitFor(5, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(0, holder.exitValue())
                assertEquals(0, run(startup).exitCode)
                assertEquals("launch", marker.readText().trim())
                assertEquals("next", record.readText().trim())
                assertEquals(0, run(previous.watchdogPoll("false", "exit 7")).exitCode)
                assertEquals("next", record.readText().trim())
                assertTrue(lock.isFile)
                assertEquals(0, run(next.stop(":")).exitCode)
            } finally {
                release.writeText("release")
                if (!holder.waitFor(2, java.util.concurrent.TimeUnit.SECONDS)) holder.destroyForcibly().waitFor()
            }
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun sharedStartupRefusesLegacyPeerRecordsWithoutGeneration() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-legacy-peer")
        val peer = dir.resolve("peer").toFile().apply { mkdir() }
        val adapter = dir.resolve("adapter").toString()
        val lifecycle = RootLifecycleTransaction(adapter, "next", dir.resolve("shared").toString(), peer.path)
        val marker = dir.resolve("action").toFile()
        val startup = lifecycle.start("echo cleanup > '${marker.path}'", "echo launch > '${marker.path}'")
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            for (name in listOf("pid", "pid6", "watch.pid")) {
                val record = File(peer, name).apply { writeText("123") }
                val denied = run(startup)
                assertFalse(denied.exitCode == 0)
                assertTrue(denied.outputTail.contains("previous adapter PID records remain"))
                assertEquals("123", record.readText())
                assertFalse(marker.exists())
                assertFalse(File(adapter, "generation").exists())
                assertTrue(record.delete())
            }
            assertEquals(0, run(startup).exitCode)
            assertEquals("launch", marker.readText().trim())
            assertEquals(0, run(lifecycle.stop(":")).exitCode)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun watchdogCleanupRetiresItsPidBeforeAllowingPeerStartup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-watchdog-retire")
        val shared = dir.resolve("shared").toString()
        val aDir = dir.resolve("a").toString()
        val bDir = dir.resolve("b").toString()
        val a = RootLifecycleTransaction(aDir, "first", shared, bDir)
        val b = RootLifecycleTransaction(bDir, "second", shared, aDir)
        val stale = RootLifecycleTransaction(aDir, "stale", shared, bDir)
        val watchPid = File(aDir, "watch.pid")
        val generation = File(aDir, "generation")
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            assertEquals(0, run(a.start(":", ":")))
            watchPid.writeText("123")
            assertEquals(0, run(stale.watchdogPoll("false", "exit 7")))
            assertEquals("123", watchPid.readText())
            assertEquals(75, run(a.watchdogPoll(":", ":")))
            assertEquals("123", watchPid.readText())
            assertFalse(run(a.watchdogPoll("false", "exit 7")) == 0)
            assertEquals("123", watchPid.readText())
            assertEquals("first", generation.readText().trim())
            assertFalse(run(b.start(":", ":")) == 0)
            // Simulate a PID-record removal error without privileged files.
            assertTrue(watchPid.delete())
            assertTrue(watchPid.mkdir())
            assertFalse(run(a.watchdogPoll("false", ":")) == 0)
            assertEquals("first", generation.readText().trim())
            assertFalse(run(b.start(":", ":")) == 0)
            assertTrue(watchPid.delete())
            watchPid.writeText("123")
            assertEquals(0, run(a.watchdogPoll("false", ":")))
            assertFalse(watchPid.exists())
            assertFalse(generation.exists())
            assertEquals(0, run(b.start(":", ":")))
            assertEquals(0, run(b.stop(":")))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun lifecyclePersistsOwnerIdentityAndRetainsItUntilCleanupSucceeds() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-owner-identity")
        val lifecycle = RootLifecycleTransaction(dir.toString(), "owner")
        val stale = RootLifecycleTransaction(dir.toString(), "stale")
        val record = dir.resolve("owner.identity").toFile()
        val generation = dir.resolve("generation").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            val identity = RootOwnerIdentity(123, "456")
            assertEquals(0, run(lifecycle.start(":", "test -s '${record.path}'", identity)))
            val fields = record.readText().trim().split(" ")
            assertEquals(4, fields.size)
            assertEquals(listOf("owner", "123", "456"), fields.take(3))
            assertTrue(fields[3].isNotEmpty())
            assertEquals(0, run(stale.stop("exit 7")))
            assertEquals(fields, record.readText().trim().split(" "))
            assertFalse(run(lifecycle.stop("exit 7")) == 0)
            assertEquals(fields, record.readText().trim().split(" "))
            assertEquals("owner", generation.readText().trim())
            assertEquals(0, run(lifecycle.stop(":")))
            assertFalse(record.exists())
            assertFalse(generation.exists())
            assertTrue(runCatching { RootOwnerIdentity(1, "456") }.isFailure)
            assertTrue(runCatching { RootOwnerIdentity(123, "bad") }.isFailure)
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun persistedOwnerInspectionDistinguishesMatchStaleAndUnknown() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-owner-status")
        val adapter = dir.resolve("adapter").toFile().apply { mkdir() }
        val proc = dir.resolve("proc").toFile().apply { mkdir() }
        val boot = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs() }
        val stat = File(proc, "123/stat").apply { parentFile?.mkdirs() }
        val generation = File(adapter, "generation").apply { writeText("owner") }
        val record = File(adapter, "owner.identity")
        val firstBoot = "11111111-1111-1111-1111-111111111111"
        val secondBoot = "22222222-2222-2222-2222-222222222222"
        fun writeStat(ticks: String, state: String = "S") {
            stat.writeText("123 (name with ) delimiter) $state " + List(18) { "0" }.joinToString(" ") + " $ticks 0")
        }
        fun inspect(): String {
            val result = RootCommandRunner.run(listOf("/bin/sh", "-c",
                RootOwnerStatus.inspect(adapter.path, proc.path),
            ))
            assertEquals(0, result.exitCode)
            return result.outputTail.trim()
        }
        try {
            boot.writeText(firstBoot)
            record.writeText("owner 123 456 $firstBoot\n")
            writeStat("456")
            assertEquals("ROOT: owner identity matches", inspect())
            for (state in listOf("Z", "X", "x")) {
                writeStat("456", state)
                assertEquals("ROOT: owner identity terminated (dead task)", inspect())
            }
            writeStat("456", "?")
            assertEquals("ROOT: owner identity unknown", inspect())
            writeStat("invalid", "S")
            assertEquals("ROOT: owner identity unknown", inspect())
            stat.writeText("124 (different PID) S " + List(18) { "0" }.joinToString(" ") + " 456 0")
            assertEquals("ROOT: owner identity unknown", inspect())
            writeStat("789", "Z")
            assertEquals("ROOT: owner identity stale (PID reused)", inspect())
            writeStat("789")
            assertEquals("ROOT: owner identity stale (PID reused)", inspect())
            assertTrue(stat.delete())
            assertEquals("ROOT: owner identity unknown", inspect())
            boot.writeText(secondBoot)
            assertEquals("ROOT: owner identity stale (boot changed)", inspect())
            record.writeText("owner 123 456 unknown\n")
            assertEquals("ROOT: owner identity unknown", inspect())
            record.writeText("other 123 456 $firstBoot\n")
            assertEquals("ROOT: owner identity unknown", inspect())
            record.writeText("owner 1 456 $firstBoot\n")
            assertEquals("ROOT: owner identity unknown", inspect())
            record.writeText("owner 0123 456 $firstBoot\n")
            assertEquals("ROOT: owner identity unknown", inspect())
            record.writeText("owner 123 invalid $firstBoot\n")
            assertEquals("ROOT: owner identity unknown", inspect())
            assertTrue(record.delete())
            assertEquals("ROOT: owner identity unknown", inspect())
            assertEquals("owner", generation.readText())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun sharedStartupRetiresOnlyVerifiedPreviousBootPeerMetadata() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-previous-boot")
        val peer = dir.resolve("peer").toFile().apply { mkdir() }
        val adapter = dir.resolve("adapter").toString()
        val proc = dir.resolve("proc").toFile().apply { mkdir() }
        val boot = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs() }
        val generation = File(peer, "generation").apply { writeText("previous") }
        val identity = File(peer, "owner.identity")
        val pid = File(peer, "pid")
        val marker = dir.resolve("launched").toFile()
        val firstBoot = "11111111-1111-1111-1111-111111111111"
        val secondBoot = "22222222-2222-2222-2222-222222222222"
        val lifecycle = RootLifecycleTransaction(
            adapter, "next", dir.resolve("shared").toString(), peer.path, proc.path,
        )
        val startup = lifecycle.start(":", "echo launched > '${marker.path}'")
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        ).exitCode
        try {
            identity.writeText("previous 123 456 $firstBoot\n")
            boot.writeText(firstBoot)
            assertFalse(run(startup) == 0)
            assertTrue(identity.exists())
            assertTrue(generation.exists())
            assertFalse(marker.exists())
            boot.writeText(secondBoot)
            pid.writeText("123")
            val visible = File(proc, "123").apply { mkdir() }
            val otherPid = File(peer, "pid6").apply { writeText("234") }
            assertFalse(run(startup) == 0)
            assertTrue(pid.exists())
            assertTrue(otherPid.exists())
            assertTrue(identity.exists())
            assertFalse(marker.exists())
            assertTrue(visible.delete())
            val watch = File(peer, "watch.pid").apply { writeText("invalid") }
            assertFalse(run(startup) == 0)
            assertTrue(pid.exists())
            assertTrue(otherPid.exists())
            assertTrue(watch.exists())
            assertFalse(marker.exists())
            assertTrue(watch.delete())
            assertTrue(watch.mkdir())
            assertFalse(run(startup) == 0)
            assertTrue(pid.exists())
            assertTrue(otherPid.exists())
            assertFalse(marker.exists())
            assertTrue(watch.delete())
            watch.writeText("345")
            identity.writeText("other 123 456 $firstBoot\n")
            assertFalse(run(startup) == 0)
            assertTrue(generation.exists())
            assertFalse(marker.exists())
            identity.writeText("previous 123 456 unknown\n")
            assertFalse(run(startup) == 0)
            assertTrue(identity.exists())
            assertFalse(marker.exists())
            identity.writeText("previous 123 456 $firstBoot\n")
            assertEquals(0, run(startup))
            assertFalse(generation.exists())
            assertFalse(identity.exists())
            assertFalse(pid.exists())
            assertFalse(otherPid.exists())
            assertFalse(watch.exists())
            assertTrue(marker.exists())
            assertEquals(0, run(lifecycle.stop(":")))
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun invalidLifecycleMetadataTypesPreventStartupAndMatchingCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-metadata-type")
        val lifecycle = RootLifecycleTransaction(dir.toString(), "owner")
        val record = dir.resolve("generation").toFile()
        val identity = dir.resolve("owner.identity").toFile()
        val marker = dir.resolve("action").toFile()
        val target = dir.resolve("unrelated").toFile().apply { writeText("unchanged") }
        val owner = RootOwnerIdentity(123, "456")
        val startup = lifecycle.start("echo cleanup > '${marker.path}'", "echo launch > '${marker.path}'", owner)
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            for (name in listOf("generation", "owner.identity", "generation.owner.tmp", "owner.identity.owner.tmp")) {
                val invalid = dir.resolve(name)
                Files.createDirectory(invalid)
                val denied = run(startup)
                assertFalse(denied.exitCode == 0)
                assertTrue(denied.outputTail.contains("invalid lifecycle metadata file type"))
                assertTrue(Files.isDirectory(invalid))
                assertFalse(marker.exists())
                Files.delete(invalid)
                Files.createSymbolicLink(invalid, target.toPath())
                assertFalse(run(startup).exitCode == 0)
                assertTrue(Files.isSymbolicLink(invalid))
                assertEquals("unchanged", target.readText())
                assertFalse(marker.exists())
                Files.delete(invalid)
            }
            assertEquals(0, run(startup).exitCode)
            assertEquals("owner", record.readText().trim())
            assertTrue(marker.delete())
            val original = identity.readText()
            assertTrue(identity.delete())
            assertTrue(identity.mkdir())
            val cleanup = lifecycle.stop("echo cleanup > '${marker.path}'")
            assertFalse(run(cleanup).exitCode == 0)
            assertFalse(marker.exists())
            assertEquals("owner", record.readText().trim())
            assertTrue(identity.delete())
            identity.writeText(original)
            assertEquals(0, run(cleanup).exitCode)
            assertTrue(marker.exists())
            assertFalse(record.exists())
            assertFalse(identity.exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun interruptedOwnerMetadataPreparationPreservesCommittedGeneration() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-owner-stage-failure")
        val first = RootLifecycleTransaction(dir.toString(), "first")
        val next = RootLifecycleTransaction(dir.toString(), "next")
        val record = dir.resolve("generation").toFile()
        val identity = dir.resolve("owner.identity").toFile()
        val marker = dir.resolve("action").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            val owner = RootOwnerIdentity(123, "456")
            assertEquals(0, run(first.start(":", ":", owner)).exitCode)
            val original = identity.readText()
            // Simulate failure of the owner staging write, without privileged
            // files or relying on chmod to deny a privileged test runner.
            val startup = next.start("echo cleanup > '${marker.path}'", "echo launch > '${marker.path}'", owner)
            val failure = run("printf() { if test \"\$1\" = '%s %s %s %s\\n'; then return 7; fi; command printf \"\$@\"; }\n" + startup)
            assertFalse(failure.exitCode == 0)
            assertEquals("first", record.readText().trim())
            assertEquals(original, identity.readText())
            assertFalse(marker.exists())
            assertEquals(0, run(next.stop("exit 7")).exitCode)
            assertEquals(original, identity.readText())
            assertEquals(0, run(first.stop(":")).exitCode)
            assertFalse(identity.exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }

    @Test fun missingGenerationWithOwnerMetadataDoesNotReportSuccessfulCleanup() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-owner-unmatched")
        val lifecycle = RootLifecycleTransaction(dir.toString(), "owner")
        val record = dir.resolve("generation").toFile()
        val identity = dir.resolve("owner.identity").toFile()
        val marker = dir.resolve("action").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            assertEquals(0, run(lifecycle.start(":", ":", RootOwnerIdentity(123, "456"))).exitCode)
            val saved = identity.readText()
            assertTrue(record.delete())
            val cleanup = "echo cleanup > '${marker.path}'"
            val stop = run(lifecycle.stop(cleanup))
            assertFalse(stop.exitCode == 0)
            assertTrue(stop.outputTail.contains("unmatched owner metadata remains"))
            assertFalse(run(lifecycle.watchdogPoll("false", cleanup)).exitCode == 0)
            assertEquals(saved, identity.readText())
            assertFalse(marker.exists())
            record.writeText("owner\n")
            assertEquals(0, run(lifecycle.stop(cleanup)).exitCode)
            assertTrue(marker.exists())
            assertFalse(identity.exists())
            assertFalse(record.exists())
        } finally {
            dir.toFile().deleteRecursively()
        }
    }


    @Test fun failedOwnerPublicationFencesMatchingGenerationUntilMetadataIsRepaired() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-owner-publication-failure")
        val first = RootLifecycleTransaction(dir.toString(), "first")
        val next = RootLifecycleTransaction(dir.toString(), "next")
        val record = dir.resolve("generation").toFile()
        val identity = dir.resolve("owner.identity").toFile()
        val staged = dir.resolve("owner.identity.next.tmp").toFile()
        val marker = dir.resolve("action").toFile()
        fun run(script: String) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 10_000,
        )
        try {
            val owner = RootOwnerIdentity(123, "456")
            assertEquals(0, run(first.start(":", ":", owner)).exitCode)
            val saved = identity.readText()
            val action = "echo action > '${marker.path}'"
            val startup = next.start(action, action, owner)
            // Fail exactly the second metadata rename, after publication of generation.
            val failed = run("mv() { if test \"\$3\" = '${identity.path}'; then return 7; fi; command mv \"\$@\"; }\n" + startup)
            assertFalse(failed.exitCode == 0)
            assertEquals("next", record.readText().trim())
            assertEquals(saved, identity.readText())
            assertTrue(staged.exists())
            assertFalse(marker.exists())
            assertFalse(run(next.alive(action)).exitCode == 0)
            val stop = run(next.stop(action))
            assertFalse(stop.exitCode == 0)
            assertTrue(stop.outputTail.contains("inconsistent owner metadata"))
            assertFalse(run(next.watchdogPoll(action, action)).exitCode == 0)
            assertFalse(marker.exists())
            assertEquals(saved, identity.readText())
            assertEquals(0, run(first.stop(action)).exitCode)
            assertFalse(marker.exists())
            // A matching record restores the normal lifecycle. This fixture
            // simulates deliberate repair; it does not enable auto-recovery.
            identity.writeText(staged.readText())
            assertEquals(0, run(next.alive(":")).exitCode)
            assertEquals(0, run(next.stop(action)).exitCode)
            assertTrue(marker.exists())
            assertFalse(identity.exists())
            assertFalse(record.exists())
            // The same failure on a fresh start leaves no committed owner
            // record at all; a matching staging record still fences cleanup.
            assertTrue(staged.delete())
            assertTrue(marker.delete())
            val freshFailure = run("mv() { if test \"\$3\" = '${identity.path}'; then return 7; fi; command mv \"\$@\"; }\n" + startup)
            assertFalse(freshFailure.exitCode == 0)
            assertEquals("next", record.readText().trim())
            assertFalse(identity.exists())
            assertTrue(staged.exists())
            assertFalse(run(next.alive(action)).exitCode == 0)
            assertFalse(run(next.stop(action)).exitCode == 0)
            assertFalse(run(next.watchdogPoll(action, action)).exitCode == 0)
            assertFalse(marker.exists())
        } finally {
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
