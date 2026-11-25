package com.dpsmpx.dppass.app

import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class RootCommandRunnerTest {
    @Test
    fun drainsLargeOutputAndKeepsOnlyBoundedTail() {
        if (!File("/bin/sh").canExecute()) return
        val result = RootCommandRunner.run(
            listOf("/bin/sh", "-c", "head -c 262144 /dev/zero | tr '\\000' x; printf END; exit 7"),
            timeoutMillis = 10_000,
        )
        assertEquals(7, result.exitCode)
        assertEquals(400, result.outputTail.length)
        assertTrue(result.outputTail.endsWith("END"))
    }

    @Test
    fun preservesExitStatusAndMergedOutput() {
        if (!File("/bin/sh").canExecute()) return
        val result = RootCommandRunner.run(
            listOf("/bin/sh", "-c", "printf first; printf second >&2"),
            timeoutMillis = 5_000,
        )
        assertEquals(0, result.exitCode)
        assertEquals("firstsecond", result.outputTail)
    }

    @Test
    fun timeoutIsReportedInsteadOfSuccess() {
        if (!File("/bin/sh").canExecute()) return
        val failure = assertFailsWith<IllegalStateException> {
            RootCommandRunner.run(listOf("/bin/sh", "-c", "exec sleep 10"), timeoutMillis = 100)
        }
        assertTrue(failure.message.orEmpty().contains("timeout"))
    }
}
