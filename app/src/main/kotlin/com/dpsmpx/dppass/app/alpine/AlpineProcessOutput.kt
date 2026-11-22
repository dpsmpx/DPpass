package com.dpsmpx.dppass.app.alpine

import java.io.IOException
import java.io.InputStream

/**
 * Consume the private strategy daemon's merged stdout/stderr without storing
 * user traffic or retaining subprocess diagnostics in app logs.
 *
 * Android's Process.destroy()/destroyForcibly() can close the underlying
 * FileInputStream from a different thread while read() is blocking. Android
 * then throws InterruptedIOException ("read interrupted by close() on
 * another thread"). This is expected when the VPN service is stopped or its
 * startup fails, and must never reach the application's uncaught-exception
 * handler. The process readiness probe and liveness watchdog report actual
 * strategy-daemon failures separately.
 */
internal object AlpineProcessOutput {
    fun drain(input: InputStream) {
        try {
            input.use { stream ->
                val buffer = ByteArray(2048)
                while (stream.read(buffer) != -1) {
                    // Deliberately discard stdout/stderr; do not log payloads.
                }
            }
        } catch (_: IOException) {
            // Normal on Android when another thread terminates/cleans up
            // Process streams. There is no safe recovery on this reader.
        }
    }
}
