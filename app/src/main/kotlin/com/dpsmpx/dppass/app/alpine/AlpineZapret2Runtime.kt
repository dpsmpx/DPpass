package com.dpsmpx.dppass.app.alpine

import android.content.Context
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Process
import java.io.File
import java.util.concurrent.TimeUnit

/**
 * Per-VPN-session unprivileged Alpine strategy daemon. Android owns the
 * VPN TUN and protected socket IO, Alpine owns TLS/QUIC strategy decisions.
 *
 * The Unix socket is private to the app UID. No network port, external
 * proxy, exported activity/service, NFQUEUE or Android root is involved.
 */
internal class AlpineZapret2Runtime private constructor(
    val socketPath: String,
    private val process: java.lang.Process,
    private val socket: File,
) : AutoCloseable {
    val isAlive: Boolean get() = process.isAlive && socket.exists()

    override fun close() {
        process.destroy()
        if (!process.waitFor(500, TimeUnit.MILLISECONDS)) {
            process.destroyForcibly()
            process.waitFor(500, TimeUnit.MILLISECONDS)
        }
        // Do not unlink a live daemon's listening pathname after a
        // timed-out termination. A subsequent session uses a fresh name.
        if (!process.isAlive &&
            (java.nio.file.Files.isSymbolicLink(socket.toPath()) || !socket.isDirectory)) {
            socket.delete()
        }
    }

    companion object {
        private const val MAX_WAIT_MS = 8_000L

        fun start(context: Context): AlpineZapret2Runtime {
            val app = context.applicationContext
            check(AlpineFiles.supported(app)) { "Alpine PRoot is not bundled for this ABI" }
            AlpineFiles.install(app)
            val layout = AlpineFiles.layout(app)
            val guestDir = File(layout.rootfs, "root")
            check(guestDir.isDirectory) { "Alpine rootfs missing /root" }
            val name = ".z2-" + Process.myPid() + "-" +
                (System.nanoTime() and 0xffff).toString(16) + ".sock"
            val socket = File(guestDir, name)
            check(AlpinePlannerReadiness.validSocketPath(socket.path)) { "invalid private Unix socket path" }
            check(!socket.exists()) { "Alpine socket already exists" }
            val argv = AlpineArgs.command(layout,
                listOf("/usr/local/bin/dppass-zapret2", "--serve", "/root/" + name))
            val spawned = ProcessBuilder(argv).apply {
                directory(app.filesDir)
                redirectErrorStream(true)
                environment().clear()
                environment().putAll(AlpineArgs.environment(layout))
            }.start()
            // Draining prevents a noisy daemon from blocking on its pipe.
            // Process.destroy() can interrupt a read from another thread on
            // Android; this is expected during failed VPN startup/shutdown,
            // not an uncaught fatal exception.
            Thread({
                AlpineProcessOutput.drain(spawned.inputStream)
            }, "dppass-zapret2-alpine-io").apply { isDaemon = true }.start()
            try {
                val deadline = android.os.SystemClock.elapsedRealtime() + MAX_WAIT_MS
                while (android.os.SystemClock.elapsedRealtime() < deadline && spawned.isAlive) {
                    if (socket.exists() && probe(socket.path) && spawned.isAlive) {
                        return AlpineZapret2Runtime(socket.path, spawned, socket)
                    }
                    Thread.sleep(40)
                }
                error("Alpine Zapret2 strategy daemon did not become ready")
            } catch (e: Exception) {
                spawned.destroyForcibly()
                // Preserve interruption and never unlink while the process
                // could still own a listening socket.
                if (e !is InterruptedException) {
                    try {
                        spawned.waitFor(500, TimeUnit.MILLISECONDS)
                    } catch (_: InterruptedException) {
                        Thread.currentThread().interrupt()
                    }
                } else {
                    Thread.currentThread().interrupt()
                }
                if (!spawned.isAlive && !socket.isDirectory) socket.delete()
                throw e
            }
        }

        private fun probe(path: String): Boolean = runCatching {
            LocalSocket().use { connection ->
                connection.connect(LocalSocketAddress(path, LocalSocketAddress.Namespace.FILESYSTEM))
                connection.soTimeout = 500
                connection.outputStream.write(AlpinePlannerReadiness.request())
                connection.outputStream.flush()
                AlpinePlannerReadiness.matches(connection.inputStream)
            }
        }.getOrDefault(false)
    }
}
