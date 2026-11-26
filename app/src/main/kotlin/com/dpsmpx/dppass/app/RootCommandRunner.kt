package com.dpsmpx.dppass.app

import java.util.concurrent.TimeUnit
import java.util.concurrent.FutureTask
import java.util.concurrent.ExecutionException
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
    private const val TERMINATION_TIMEOUT_MS = 1_000L

    data class Result(val exitCode: Int, val outputTail: String)

    fun run(command: List<String>, timeoutMillis: Long = 15_000L): Result {
        val args = command.toList()
        require(args.isNotEmpty() && args[0].isNotBlank() && timeoutMillis > 0)
        require(args.none { '\u0000' in it }) { "ROOT: invalid command argument" }
        return runProcess(ProcessBuilder(args).redirectErrorStream(true).start(), timeoutMillis)
    }

    // Caller owns this immediate child only, not an arbitrary descendant tree.
    // Exposed internally to exercise termination and stream failures without su.
    internal fun runProcess(process: Process, timeoutMillis: Long): Result {
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
        var primary: Throwable? = null
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
            } catch (failure: ExecutionException) {
                throw IllegalStateException("su: output drain failed", failure.cause ?: failure)
            }
            return Result(process.exitValue(), tail.text())
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            // Interrupted waitFor clears the interrupt bit. Restore it only
            // after a bounded attempt to terminate our immediate child.
            var interrupted = Thread.interrupted() || primary is InterruptedException
            val cleanup = try {
                if (process.isAlive) {
                    process.destroyForcibly()
                    check(process.waitFor(TERMINATION_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                        "su: immediate child termination unconfirmed"
                    }
                }
                null
            } catch (failure: Exception) {
                if (failure is InterruptedException) interrupted = true
                failure
            } finally {
                if (!drain.isDone) drain.cancel(true)
                if (interrupted) Thread.currentThread().interrupt()
            }
            if (cleanup != null) {
                val original = primary
                if (original == null) throw cleanup
                if (original !== cleanup) original.addSuppressed(cleanup)
            }
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
