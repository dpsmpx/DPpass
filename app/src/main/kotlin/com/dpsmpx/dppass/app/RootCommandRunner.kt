package com.dpsmpx.dppass.app

import java.util.concurrent.TimeUnit
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeoutException

/**
 * Common legacy ROOT command lifecycle. The caller still owns permission,
 * rule installation and rollback. Drain stdout/stderr concurrently with
 * waitFor so a full pipe cannot prevent the shell from exiting.
 *
 * Only the last 400 bytes are retained; a daemon reader and bounded join
 * prevent an inherited stdout descriptor from blocking the caller.
 */
internal object RootCommandRunner {
    private const val TAIL_BYTES = 400
    private const val DRAIN_TIMEOUT_MS = 250L

    data class Result(val exitCode: Int, val outputTail: String)

    fun run(command: List<String>, timeoutMillis: Long = 15_000L): Result {
        require(command.isNotEmpty() && timeoutMillis > 0)
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val tail = OutputTail()
        val drain = FutureTask<Unit> {
            process.inputStream.use { input ->
                val buffer = ByteArray(4096)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    if (count > 0) tail.append(buffer, count)
                }
            }
        }
        val reader = Thread(drain, "dppass-root-output").apply { isDaemon = true }
        try {
            reader.start()
            // su commands are noninteractive after the external root grant.
            process.outputStream.close()
            if (!process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS)) {
                error("su: timeout")
            }
            try {
                drain.get(DRAIN_TIMEOUT_MS, TimeUnit.MILLISECONDS)
            } catch (_: TimeoutException) {
                // A descendant may still own the pipe. Do not wait forever
                // for EOF or close a blocking stream on the caller thread.
                error("su: output drain timeout")
            }
            return Result(process.exitValue(), tail.text())
        } finally {
            if (process.isAlive) process.destroyForcibly()
            if (!drain.isDone) drain.cancel(true)
        }
    }

    private class OutputTail {
        private val ring = ByteArray(TAIL_BYTES)
        private var next = 0
        private var size = 0

        fun append(bytes: ByteArray, count: Int) {
            for (i in maxOf(0, count - ring.size) until count) {
                ring[next] = bytes[i]
                next = (next + 1) % ring.size
                size = minOf(size + 1, ring.size)
            }
        }

        fun text(): String {
            val start = (next - size + ring.size) % ring.size
            return ByteArray(size) { i -> ring[(start + i) % ring.size] }.decodeToString()
        }
    }
}
