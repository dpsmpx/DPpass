package com.dpsmpx.dppass.app.alpine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class AlpineArgsTest {
    private val layout = AlpineArgs.Layout("/libs/libproot.so", "/libs/libproot-loader.so", "/private/rootfs", "/private/tmp")

    @Test fun shellHasSafeBindingsAndFakeRootOnly() {
        val args = AlpineArgs.shell(layout)
        assertEquals("/libs/libproot.so", args.first())
        assertEquals(listOf("/bin/sh", "-l"), args.takeLast(2))
        assertTrue("--kill-on-exit" in args)
        assertTrue("--link2symlink" in args)
        assertTrue("-0" in args)
        assertTrue("-r" in args)
        assertTrue("/private/rootfs" in args)
        assertFalse("/sys" in args)
        assertFalse("/dev/binder" in args)
    }

    @Test fun apkRunsWithoutProcAsRequiredByAndroid() {
        val apk = AlpineArgs.command(layout, listOf("apk", "info"))
        val shell = AlpineArgs.shell(layout)
        assertFalse("/proc" in apk)
        assertTrue("/proc" in shell)
    }

    @Test fun guestEnvironmentDoesNotInheritAndroidSecrets() {
        val env = AlpineArgs.environment(layout)
        assertEquals("/libs/libproot-loader.so", env["PROOT_LOADER"])
        assertEquals("dumb", env["TERM"])
        assertFalse("HOME_ANDROID" in env)
        assertEquals("/root", env["HOME"])
    }
}
