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

    @Test
    fun rejectsMalformedCommandsBeforeStartingProcess() {
        for (command in listOf(emptyList(), listOf(" "), listOf("/bin/sh", "bad\u0000arg"))) {
            assertFailsWith<IllegalArgumentException> { RootCommandRunner.run(command) }
        }
        assertFailsWith<IllegalArgumentException> { RootCommandRunner.run(listOf("/bin/sh"), 0) }
    }

    @Test
    fun timeoutConfirmsImmediateChildTermination() {
        if (!File("/bin/sh").canExecute()) return
        val process = ProcessBuilder("/bin/sh", "-c", "exec sleep 10").start()
        try {
            val failure = assertFailsWith<IllegalStateException> {
                RootCommandRunner.runProcess(process, 100)
            }
            assertEquals("su: timeout", failure.message)
            assertTrue(!process.isAlive)
        } finally {
            process.destroyForcibly()
        }
    }

    @Test
    fun interruptedWaitTerminatesChildAndRestoresInterrupt() {
        if (!File("/bin/sh").canExecute()) return
        val process = ProcessBuilder("/bin/sh", "-c", "exec sleep 10").start()
        val result = java.util.concurrent.atomic.AtomicReference<Throwable?>()
        val interrupted = java.util.concurrent.atomic.AtomicBoolean()
        val worker = Thread {
            Thread.currentThread().interrupt()
            try {
                RootCommandRunner.runProcess(process, 5000)
            } catch (failure: Throwable) {
                result.set(failure)
                interrupted.set(Thread.currentThread().isInterrupted)
            }
        }
        try {
            worker.start()
            worker.join(5000)
            assertTrue(!worker.isAlive)
            assertTrue(result.get() is InterruptedException)
            assertTrue(interrupted.get())
            assertTrue(!process.isAlive)
        } finally {
            process.destroyForcibly()
            if (worker.isAlive) worker.interrupt()
        }
    }

    private class ControlledProcess(
        private val refuseTermination: Boolean = false,
        private val readFailure: Boolean = false,
    ) : Process() {
        private var running = !readFailure
        var destroyCalls = 0
        private val output = java.io.ByteArrayOutputStream()
        private val input = object : java.io.InputStream() {
            override fun read(): Int {
                if (readFailure) throw java.io.IOException("fixture read failure")
                return -1
            }
        }
        override fun getOutputStream(): java.io.OutputStream = output
        override fun getInputStream(): java.io.InputStream = input
        override fun getErrorStream(): java.io.InputStream = java.io.ByteArrayInputStream(byteArrayOf())
        override fun waitFor(): Int = exitValue()
        override fun waitFor(timeout: Long, unit: java.util.concurrent.TimeUnit): Boolean = !running
        override fun exitValue(): Int {
            check(!running)
            return 0
        }
        override fun isAlive(): Boolean = running
        override fun destroy() {
            destroyCalls++
            if (!refuseTermination) running = false
        }
        override fun destroyForcibly(): Process {
            destroy()
            return this
        }
    }

    @Test
    fun unconfirmedTerminationDoesNotHideOriginalTimeout() {
        val process = ControlledProcess(refuseTermination = true)
        val failure = assertFailsWith<IllegalStateException> {
            RootCommandRunner.runProcess(process, 100)
        }
        assertEquals("su: timeout", failure.message)
        assertEquals(1, process.destroyCalls)
        assertEquals("su: immediate child termination unconfirmed", failure.suppressed.single().message)
    }

    @Test
    fun drainFailureIsReportedWithOriginalCause() {
        val process = ControlledProcess(readFailure = true)
        val failure = assertFailsWith<IllegalStateException> {
            RootCommandRunner.runProcess(process, 100)
        }
        assertEquals("su: output drain failed", failure.message)
        assertTrue(failure.cause is java.io.IOException)
        assertEquals("fixture read failure", failure.cause?.message)
        assertEquals(0, process.destroyCalls)
    }
}
