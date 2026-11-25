package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootChildIdentityTest {
    @Test fun childRecordsBindGenerationPidStartTicksBootAndExpectedExecutable() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-child-identity").toFile()
        val proc = File(dir, "proc")
        val boot = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs() }
        val task = File(proc, "123").apply { mkdirs() }
        val stat = File(task, "stat")
        val exe = File(task, "exe")
        val pid = File(dir, "pid")
        val record = File(dir, "pid.identity")
        val temporary = File(dir, "pid.identity.launch.tmp")
        val executable = File(dir, "daemon").apply { writeText("fixture") }
        val firstBoot = "11111111-1111-1111-1111-111111111111"
        val secondBoot = "22222222-2222-2222-2222-222222222222"
        fun writeStat(ticks: String, state: String = "S", taskPid: Int = 123) {
            stat.writeText("$taskPid (name ) with spaces) $state " + List(18) { "0" }.joinToString(" ") + " $ticks 0")
        }
        fun run(script: String): Int = RootCommandRunner.run(
            listOf("/bin/sh", "-c", script), timeoutMillis = 5_000,
        ).exitCode
        val capture = RootChildIdentity.captureExecutable(pid.path, "launch", executable.path, proc.path)
        val match = RootChildIdentity.matchesExecutable(pid.path, "launch", executable.path, proc.path)
        val gone = RootChildIdentity.sameBootGone(pid.path, "launch", proc.path)
        fun neither() {
            assertFalse(run(match) == 0)
            assertFalse(run(gone) == 0)
        }
        try {
            boot.writeText(firstBoot)
            pid.writeText("123\n")
            writeStat("456")
            Files.createSymbolicLink(exe.toPath(), executable.toPath())
            assertEquals(0, run(capture))
            val saved = "v1 launch 123 456 $firstBoot\n"
            assertEquals(saved, record.readText())
            assertFalse(temporary.exists())
            assertEquals(0, run(match))
            assertFalse(run(gone) == 0)
            assertFalse(run(RootChildIdentity.matchesExecutable(pid.path, "other", executable.path, proc.path)) == 0)
            assertFalse(run(RootChildIdentity.sameBootGone(pid.path, "other", proc.path)) == 0)
            assertFalse(run(RootChildIdentity.matchesExecutable(pid.path, "launch", executable.path + "-other", proc.path)) == 0)

            // The exact executable is unchanged, but the PID now belongs
            // to a different task. Never treat this as a live owned child.
            writeStat("789")
            assertFalse(run(match) == 0)
            assertEquals(0, run(gone))
            writeStat("456", "Z")
            assertFalse(run(match) == 0)
            assertEquals(0, run(gone))
            writeStat("456", "?")
            neither()
            writeStat("bad", "Z")
            neither()
            writeStat("456", taskPid = 124)
            neither()
            assertTrue(stat.delete())
            neither()
            writeStat("456")
            boot.writeText(secondBoot)
            neither()
            boot.writeText("invalid")
            neither()
            boot.writeText(firstBoot)
            for (invalid in listOf("", "1", "0123", "2147483648", "123 456", "124")) {
                pid.writeText(invalid)
                neither()
            }
            pid.writeText("123\n")
            for (invalid in listOf("v1 launch 123 bad $firstBoot", "v1 other 123 456 $firstBoot", "v1 launch 124 456 $firstBoot", "v2 launch 123 456 $firstBoot")) {
                record.writeText(invalid)
                neither()
            }
            record.writeText(saved)

            // Failed staging publication preserves the committed record.
            writeStat("789")
            assertFalse(run("mv() { return 7; }\n" + capture) == 0)
            assertEquals(saved, record.readText())
            assertTrue(temporary.exists())
            assertTrue(temporary.delete())
            assertTrue(temporary.mkdir())
            assertFalse(run(capture) == 0)
            assertEquals(saved, record.readText())
            assertTrue(temporary.delete())
            assertTrue(record.delete())
            val target = File(dir, "unrelated").apply { writeText("unchanged") }
            Files.createSymbolicLink(record.toPath(), target.toPath())
            neither()
            assertFalse(run(capture) == 0)
            assertEquals("unchanged", target.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun recordedStopRequiresPositiveIdentityAndRetainsEvidenceOnUncertainty() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-child-recorded-stop").toFile()
        val proc = File(dir, "proc")
        val boot = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs() }
        val task = File(proc, "123").apply { mkdirs() }
        val stat = File(task, "stat")
        val exe = File(task, "exe")
        val pid = File(dir, "pid")
        val record = File(dir, "pid.identity")
        val signal = File(dir, "signal")
        val daemon = File(dir, "daemon").apply { writeText("fixture") }
        val bootId = "11111111-1111-1111-1111-111111111111"
        fun statLine(ticks: String, state: String = "S") =
            "123 (daemon) $state " + List(18) { "0" }.joinToString(" ") + " $ticks 0"
        val saved = "v1 owner 123 456 $bootId\n"
        val stop = RootChildIdentity.stopRecordedExecutable(pid.path, "owner", daemon.path, proc.path)
        val noSignal = "kill() { echo unexpected > '${signal.path}'; return 1; }\n"
        fun run(prefix: String = noSignal, command: String = stop) = RootCommandRunner.run(
            listOf("/bin/sh", "-c", prefix + command), timeoutMillis = 10_000,
        )
        fun reset(ticks: String = "456", state: String = "S") {
            pid.writeText("123\n")
            record.writeText(saved)
            stat.writeText(statLine(ticks, state))
            signal.delete()
        }
        fun denied(command: String = stop) {
            assertFalse(run(command = command).exitCode == 0)
            assertTrue(pid.exists())
            assertFalse(signal.exists())
        }
        try {
            boot.writeText(bootId)
            Files.createSymbolicLink(exe.toPath(), daemon.toPath())
            reset()
            record.writeText("v1 other 123 456 $bootId\n")
            denied()
            reset()
            assertTrue(record.delete())
            denied()
            reset()
            denied(RootChildIdentity.stopRecordedExecutable(pid.path, "owner", daemon.path + "-other", proc.path))
            assertEquals(saved, record.readText())
            assertTrue(stat.delete())
            denied()
            reset("456", "?")
            denied()
            reset()
            boot.writeText("22222222-2222-2222-2222-222222222222")
            denied()
            boot.writeText(bootId)

            // Positive PID reuse or dead task: retire without any signal,
            // even when the executable path is identical.
            for ((ticks, state) in listOf("789" to "S", "456" to "Z")) {
                reset(ticks, state)
                assertEquals(0, run().exitCode)
                assertFalse(pid.exists())
                assertFalse(signal.exists())
                assertEquals(saved, record.readText())
            }

            reset()
            val failed = run("kill() { echo \"\$1\" > '${signal.path}'; return 1; }\n")
            assertFalse(failed.exitCode == 0)
            assertEquals("123", signal.readText().trim())
            assertTrue(pid.exists())
            assertEquals(saved, record.readText())

            reset()
            val noExit = run("kill() { echo \"\$1\" > '${signal.path}'; return 0; }\n")
            assertFalse(noExit.exitCode == 0)
            assertTrue(pid.exists())
            assertEquals(saved, record.readText())

            reset()
            val disappeared = run("kill() { rm -f '${stat.path}'; return 0; }\n")
            assertFalse(disappeared.exitCode == 0)
            assertTrue(pid.exists())
            assertEquals(saved, record.readText())

            // Simulate a positive post-signal death proof without touching
            // any real process. The sidecar remains for lifecycle retirement.
            reset()
            val terminated = run("kill() { echo \"\$1\" > '${signal.path}'; " +
                "printf '%s\\n' '${statLine("456", "Z")}' > '${stat.path}'; return 0; }\n")
            assertEquals(0, terminated.exitCode)
            assertEquals("123", signal.readText().trim())
            assertFalse(pid.exists())
            assertEquals(saved, record.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun scriptIdentityRequiresAnExactArgumentAndDoesNotSignalProcesses() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-child-watch").toFile()
        val proc = File(dir, "proc")
        val boot = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs() }
        val task = File(proc, "123").apply { mkdirs() }
        val stat = File(task, "stat")
        val cmdline = File(task, "cmdline")
        val pid = File(dir, "watch.pid")
        val record = File(dir, "watch.pid.identity")
        val script = File(dir, "watch.sh").path
        fun run(command: String): Int = RootCommandRunner.run(
            listOf("/bin/sh", "-c", "kill() { exit 42; }\n" + command), timeoutMillis = 5_000,
        ).exitCode
        val capture = RootChildIdentity.captureScript(pid.path, "launch", script, proc.path)
        val matches = RootChildIdentity.matchesScript(pid.path, "launch", script, proc.path)
        try {
            boot.writeText("11111111-1111-1111-1111-111111111111")
            pid.writeText("123")
            stat.writeText("123 (sh) S " + List(18) { "0" }.joinToString(" ") + " 456 0")
            cmdline.writeText("sh\u0000$script-unrelated\u0000")
            assertFalse(run(capture) == 0)
            assertFalse(record.exists())
            cmdline.writeText("sh\u0000$script\u0000")
            assertEquals(0, run(capture))
            assertEquals(0, run(matches))
            cmdline.writeText("sh\u0000$script-unrelated\u0000")
            assertFalse(run(matches) == 0)
            assertFalse(run(RootChildIdentity.sameBootGone(pid.path, "launch", proc.path)) == 0)
        } finally {
            dir.deleteRecursively()
        }
    }
}
