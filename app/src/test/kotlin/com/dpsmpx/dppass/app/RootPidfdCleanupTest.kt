package com.dpsmpx.dppass.app

import java.io.File
import java.nio.file.Files
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootPidfdCleanupTest {
    @Test fun unpairedIdentityRequiresNoSignalGoneProofBeforeRetirement() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-unpaired-child").toFile()
        val generation = File(dir, "generation")
        val pid = File(dir, "pid")
        val identity = File(dir, "pid.identity")
        val marker = File(dir, "pidfd.required")
        val helper = File(dir, "root-pidfd")
        val calls = File(dir, "calls")
        val boot = "11111111-1111-1111-1111-111111111111"
        val record = "v1 owner 123 456 $boot\n"
        val stop = RootPidfdCleanup.stopExecutable(dir.path, "pid", "/fixture/daemon")
        fun run() = RootCommandRunner.run(listOf("/bin/sh", "-c",
            "kill() { exit 99; }\n" + stop), timeoutMillis = 5000).exitCode
        fun install(result: Int) {
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; " +
                "gone) printf '%s\\n' \"\$@\" > '${calls.path}'; exit $result;; *) exit 99;; esac\n")
            assertTrue(helper.setExecutable(true))
        }
        try {
            generation.writeText("owner\n")
            marker.writeText("v1\n")
            assertEquals(0, run())
            identity.writeText(record)
            assertFalse(run() == 0)
            install(2)
            assertFalse(run() == 0)
            assertEquals(listOf("gone", "123", "456", boot), calls.readLines())
            assertEquals(record, identity.readText())
            assertFalse(pid.exists())
            install(0)
            calls.delete()
            identity.writeText("v1 stale 123 456 $boot\n")
            assertFalse(run() == 0)
            assertFalse(calls.exists())
            identity.writeText(record)
            marker.writeText("invalid\n")
            assertFalse(run() == 0)
            assertFalse(calls.exists())
            marker.writeText("v1\n")
            assertEquals(0, run())
            assertEquals(listOf("gone", "123", "456", boot), calls.readLines())
            // Only the enclosing lifecycle transaction retires the sidecar.
            assertEquals(record, identity.readText())
            assertFalse(pid.exists())
            marker.delete()
            helper.delete()
            assertFalse(run() == 0)
            assertEquals(record, identity.readText())
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun missingIdentityCanBeRetiredOnlyAfterNativeAbsenceProof() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-legacy-child").toFile()
        val pid = File(dir, "pid")
        val marker = File(dir, "pidfd.required")
        val helper = File(dir, "root-pidfd")
        val calls = File(dir, "calls")
        val bootFile = File("/proc/sys/kernel/random/boot_id")
        if (!bootFile.canRead()) {
            dir.deleteRecursively()
            return
        }
        val boot = bootFile.readText().trim()
        val stop = RootPidfdCleanup.stopExecutable(dir.path, "pid", "/fixture/daemon")
        fun run() = RootCommandRunner.run(listOf("/bin/sh", "-c",
            "kill() { echo unexpected; exit 99; }\n" + stop), timeoutMillis = 5000)
        fun install(result: Int) {
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; " +
                "*) printf '%s\\n' \"\$@\" > '${calls.path}'; exit $result;; esac\n")
            assertTrue(helper.setExecutable(true))
        }
        try {
            for (strict in listOf(false, true)) {
                if (strict) marker.writeText("v1\n")
                pid.writeText("123\n")
                install(2)
                assertFalse(run().exitCode == 0)
                assertEquals("123\n", pid.readText())
                assertEquals(listOf("absent", "123", boot), calls.readLines())
                install(0)
                assertEquals(0, run().exitCode)
                assertFalse(pid.exists())
                assertEquals(listOf("absent", "123", boot), calls.readLines())
                assertEquals(strict, marker.exists())
            }
        } finally {
            dir.deleteRecursively()
        }
    }

    @Test fun recordedCleanupNeverFallsBackAfterHelperFailure() {
        if (!File("/bin/sh").canExecute()) return
        val dir = Files.createTempDirectory("dppass-recorded-cleanup").toFile()
        val generation = File(dir, "generation")
        val pid = File(dir, "pid")
        val identity = File(dir, "pid.identity")
        val strict = File(dir, "pidfd.required")
        val helper = File(dir, "root-pidfd")
        val call = File(dir, "call")
        val boot = "11111111-1111-1111-1111-111111111111"
        val saved = "v1 owner 123 456 $boot\n"
        val stop = RootPidfdCleanup.stopExecutable(dir.path, "pid", "/fixture/daemon")
        fun run() = RootCommandRunner.run(listOf("/bin/sh", "-c",
            "kill() { echo unexpected; exit 99; }\n" + stop), timeoutMillis = 5000)
        fun install(result: Int) {
            helper.writeText("#!/bin/sh\ncase \"\$1\" in --version) echo dppass-root-pidfd/1;; " +
                "gone) exit 2;; stop-executable) printf '%s\\n' \"\$@\" > '${call.path}'; exit $result;; *) exit 2;; esac\n")
            assertTrue(helper.setExecutable(true))
        }
        try {
            generation.writeText("owner\n")
            pid.writeText("123\n")
            identity.writeText(saved)
            strict.writeText("v1\n")
            assertFalse(run().exitCode == 0)
            assertTrue(pid.exists())
            install(2)
            assertFalse(run().exitCode == 0)
            assertTrue(pid.exists())
            assertEquals(saved, identity.readText())
            assertEquals(listOf("stop-executable", "123", "456", boot, "/fixture/daemon", "2000"), call.readLines())
            call.delete()
            identity.writeText("v1 stale 123 456 $boot\n")
            assertFalse(run().exitCode == 0)
            assertFalse(call.exists())
            assertTrue(pid.exists())
            assertTrue(identity.delete())
            assertFalse(run().exitCode == 0)
            assertTrue(pid.exists())
            identity.writeText(saved)
            install(0)
            assertEquals(0, run().exitCode)
            assertFalse(pid.exists())
            assertEquals(saved, identity.readText())
        } finally {
            dir.deleteRecursively()
        }
    }
}
