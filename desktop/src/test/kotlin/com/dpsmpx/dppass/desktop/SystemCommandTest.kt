package com.dpsmpx.dppass.desktop

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Системные программы (T17): абсолютный путь, аргументы списком, предел времени. */
class SystemCommandTest {
    @Test
    fun runsTheFirstExecutableWithArgumentsAsIs() {
        val r = SystemCommand.run(listOf("/nonexistent/echo", "/usr/bin/echo", "/bin/echo"), "echo", listOf("a b", "\$HOME;"))
        assertEquals(0, r.code)
        assertEquals("a b \$HOME;\n", r.output, "без shell: ни подстановок, ни разбиения аргументов")
    }

    @Test
    fun missingProgramIsNotFoundNotACrash() {
        val r = SystemCommand.run(listOf("/nonexistent/nmcli"), "nmcli", emptyList())
        assertEquals(SystemCommand.NOT_FOUND, r.code)
        assertTrue("nmcli" in r.output)
    }

    @Test
    fun hangingProgramIsStoppedAtTheLimit() {
        val r = SystemCommand.run(listOf("/usr/bin/sleep", "/bin/sleep"), "sleep", listOf("30"), timeoutSeconds = 1)
        assertEquals(SystemCommand.TIMED_OUT, r.code)
    }
}
