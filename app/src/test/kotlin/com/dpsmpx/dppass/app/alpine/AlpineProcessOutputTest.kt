package com.dpsmpx.dppass.app.alpine

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.io.ByteArrayInputStream
import java.io.IOException
import java.io.InputStream
import java.io.InterruptedIOException

class AlpineProcessOutputTest {
    @Test fun normalEndOfFileIsDrainedAndClosed() {
        val bytes = ByteArray(8192) { (it % 256).toByte() }
        val input = object : ByteArrayInputStream(bytes) {
            var closed = false
            override fun close() {
                closed = true
                super.close()
            }
        }
        AlpineProcessOutput.drain(input)
        assertTrue(input.closed)
        assertArrayEquals(ByteArray(0), input.readAllBytes())
    }

    @Test fun interruptedReadByConcurrentProcessCloseIsNotFatal() {
        val input = object : InputStream() {
            var closed = false
            override fun read(): Int = throw InterruptedIOException(
                "read interrupted by close() on another thread")
            override fun close() { closed = true }
        }
        // This exact Android 15 exception used to escape a daemon thread
        // and trigger the application's global FATAL handler.
        AlpineProcessOutput.drain(input)
        assertTrue(input.closed)
    }

    @Test fun unexpectedPipeIoFailureCannotCrashReaderThread() {
        val input = object : InputStream() {
            var closed = false
            override fun read(): Int = throw IOException("process pipe unavailable")
            override fun close() { closed = true }
        }
        AlpineProcessOutput.drain(input)
        assertTrue(input.closed)
    }

    @Test fun programmerErrorsAreNotSilenced() {
        val input = object : InputStream() {
            override fun read(): Int = throw IllegalStateException("bug")
        }
        assertThrows(IllegalStateException::class.java) { AlpineProcessOutput.drain(input) }
    }
}
