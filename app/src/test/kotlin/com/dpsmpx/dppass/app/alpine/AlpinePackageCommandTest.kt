package com.dpsmpx.dppass.app.alpine

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class AlpinePackageCommandTest {
    @Test
    fun buildArgvWithoutShellOrProc() {
        assertEquals(
            listOf("/sbin/apk", "add", "-U", "--no-progress", "curl", "git"),
            AlpinePackageCommand.arguments("add", "curl  git"),
        )
    }

    @Test
    fun rejectInjectedOptionsAndInvalidCommands() {
        for (name in listOf("--force", "curl;rm", "../passwd", "https://example.com", "A\u0000B")) {
            assertThrows(IllegalArgumentException::class.java) {
                AlpinePackageCommand.arguments("add", name)
            }
        }
        assertThrows(IllegalArgumentException::class.java) {
            AlpinePackageCommand.arguments("del", "curl")
        }
        assertThrows(IllegalArgumentException::class.java) {
            AlpinePackageCommand.arguments("add", "")
        }
    }

    @Test
    fun updatesCannotContainPackageNames() {
        assertEquals(listOf("/sbin/apk", "update", "-U", "--no-progress"), AlpinePackageCommand.arguments("update", ""))
        assertThrows(IllegalArgumentException::class.java) {
            AlpinePackageCommand.arguments("update", "curl")
        }
    }
}
