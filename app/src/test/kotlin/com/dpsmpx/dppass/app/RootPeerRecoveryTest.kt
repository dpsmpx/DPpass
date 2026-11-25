package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootPeerRecoveryTest {
    @Test fun strictSameAdapterHandoverRejectsLiveOwnerAndMigratesPreviousBoot() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-strict-handover").toFile()
        val proc = File(dir, "proc")
        val boot = "11111111-1111-1111-1111-111111111111"
        val otherBoot = "22222222-2222-2222-2222-222222222222"
        val bootFile = File(proc, "sys/kernel/random/boot_id").apply { parentFile?.mkdirs(); writeText(boot) }
        val adapter = File(dir, "adapter").apply { mkdir() }
        val gen = File(adapter, "generation")
        val pid = File(adapter, "pid")
        val identity = File(adapter, "pid.identity")
        val strict = File(adapter, "pidfd.required")
        val helper = File(adapter, "root-pidfd")
        val marker = File(dir, "cleaned")
        val next = RootLifecycleTransaction(adapter.path, "next", procRoot = proc.path)
        val owner = RootOwnerIdentity(234, "567")
        fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c", script), timeoutMillis = 10000)
        val cleanup = "touch '${marker.path}'; rm -f '${pid.path}'"
        try {
            gen.writeText("v2 prior 345 678 $boot\n")
            strict.writeText("v1\n")
            pid.writeText("123")
            identity.writeText("v1 prior 123 456 $boot\n")
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; *) exit 2;; esac\n")
            assertTrue(helper.setExecutable(true))
            assertFalse(run(next.start(cleanup, ":", owner, preservePreviousOwner = true)).exitCode == 0)
            assertFalse(marker.exists())
            assertTrue(pid.exists())
            assertEquals("v2 prior 345 678 $boot\n", gen.readText())

            // A new boot invalidates old ownership, but a visible PID
            // still prevents metadata-only retirement.
            bootFile.writeText(otherBoot)
            val visible = File(proc, "123").apply { mkdir() }
            assertFalse(run(next.start(cleanup, ":", owner, preservePreviousOwner = true)).exitCode == 0)
            assertFalse(marker.exists())
            assertTrue(pid.exists())
            assertTrue(visible.delete())
            assertEquals(0, run(next.start(cleanup, ":", owner, preservePreviousOwner = true)).exitCode)
            assertTrue(marker.exists())
            assertFalse(pid.exists())
            assertFalse(identity.exists())
            assertFalse(strict.exists())
            assertTrue(gen.readText().startsWith("v2 next "))
            assertEquals(0, run(next.stop(":")).exitCode)
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun onlyPositivelyOrphanedStrictPeerMayBeRecovered() {
        if (!File("/bin/sh").canExecute()) return
        if (RootCommandRunner.run(listOf("/bin/sh", "-c", "command -v flock")).exitCode != 0) return
        val dir = Files.createTempDirectory("dppass-peer-recovery").toFile()
        val shared = File(dir, "shared")
        val old = File(dir, "old").apply { mkdirs() }
        val next = File(dir, "next")
        val proc = File(dir, "proc")
        val boot = "11111111-1111-1111-1111-111111111111"
        val bootFile = File(proc, "sys/kernel/random/boot_id").apply {
            parentFile?.mkdirs()
            writeText("$boot\n")
        }
        val generation = File(old, "generation")
        val pid = File(old, "pid")
        val identity = File(old, "pid.identity")
        val strict = File(old, "pidfd.required")
        val helper = File(old, "root-pidfd")
        val cleaned = File(dir, "cleaned")
        val launch = File(dir, "launched")
        val expected = "v2 prior 234 567 $boot\n"
        fun helperStatus(status: Int) {
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; " +
                "gone) test \"\$2 \$3 \$4\" = '234 567 $boot' || exit 2; exit $status;; *) exit 2;; esac\n")
            assertTrue(helper.setExecutable(true))
        }
        fun transaction(cleanup: String) = RootLifecycleTransaction(next.path, "next", shared.path,
            old.path, proc.path, peerCleanup = cleanup)
        fun run(script: String) = RootCommandRunner.run(listOf("/bin/sh", "-c", script), timeoutMillis = 10000)
        val cleanup = "touch '${cleaned.path}'; rm -f '${pid.path}'"
        val start = "touch '${launch.path}'"
        val tx = transaction(cleanup)
        try {
            generation.writeText(expected)
            pid.writeText("123")
            identity.writeText("v1 prior 123 456 $boot\n")
            helperStatus(0)
            assertFalse(run(tx.start(":", start)).exitCode == 0)
            assertFalse(cleaned.exists())
            strict.writeText("v1\n")
            helperStatus(2)
            assertFalse(run(tx.start(":", start)).exitCode == 0)
            assertFalse(cleaned.exists())
            helperStatus(0)
            assertFalse(run(transaction("exit 7").start(":", start)).exitCode == 0)
            assertEquals(expected, generation.readText())
            assertTrue(pid.exists())
            assertTrue(identity.exists())
            assertFalse(launch.exists())
            assertFalse(run(transaction(":").start(":", start)).exitCode == 0)
            assertTrue(pid.exists())
            assertTrue(strict.exists())
            assertEquals(0, run(tx.start(":", start)).exitCode)
            assertTrue(cleaned.exists())
            assertTrue(launch.exists())
            assertFalse(pid.exists())
            assertFalse(identity.exists())
            assertFalse(strict.exists())
            assertFalse(generation.exists())
            assertEquals(0, run(tx.stop(":")).exitCode)
        } finally {
            // Keep the fixture's boot file in the private temp directory.
            assertTrue(bootFile.exists())
            dir.deleteRecursively()
        }
    }
}
