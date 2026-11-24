package com.dpsmpx.dppass.app

import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.system.Os
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.TimeUnit

/** Original ciadpi with a same-UID, private SCM_RIGHTS socket protection service. */
internal class ByeDpiRuntime private constructor(
    val port: Int,
    val token: String,
    private val process: java.lang.Process,
    private val bound: LocalSocket,
    private val server: LocalServerSocket,
    private val path: File,
) : AutoCloseable {
    val isAlive: Boolean get() = process.isAlive && path.exists()

    override fun close() {
        process.destroy()
        if (!process.waitFor(500, TimeUnit.MILLISECONDS)) process.destroyForcibly()
        runCatching { server.close() }
        runCatching { bound.close() }
        path.delete()
    }

    companion object {
        fun executable(context: android.content.Context): File =
            File(context.applicationInfo.nativeLibraryDir, "libciadpi.so").also {
                check(it.isFile && it.canExecute()) { "Original ByeDPI executable is not bundled for this ABI" }
            }

        // First try plain, then use the upstream retry group only on its
        // documented timeout/reset/TLS-error events. Never invent success.
        val strategy = listOf("--auto=torst", "--timeout", "3", "--split", "1", "--tlsrec", "1+s")

        fun start(vpn: VpnService): ByeDpiRuntime {
            val binary = executable(vpn)
            val token = ByteArray(24).also { java.security.SecureRandom().nextBytes(it) }
                .joinToString("") { "%02x".format(it.toInt() and 255) }
            val dir = File(vpn.noBackupFilesDir, "bd").apply { mkdirs() }
            val path = File(dir, "p-" + android.os.Process.myPid() + "-" + (System.nanoTime() and 0xffff).toString(16))
            check(path.absolutePath.toByteArray().size < 100 && !path.exists())
            val bound = LocalSocket()
            var server: LocalServerSocket? = null
            var process: java.lang.Process? = null
            try {
                bound.bind(LocalSocketAddress(path.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                val listener = LocalServerSocket(bound.fileDescriptor)
                server = listener
                Thread({
                    while (true) {
                        val client = try { listener.accept() } catch (_: Exception) { break }
                        client.use { socket ->
                            runCatching {
                                socket.soTimeout = 500
                                if (socket.peerCredentials.uid != android.os.Process.myUid()) return@runCatching
                                val request = socket.inputStream.read()
                                val fds = socket.ancillaryFileDescriptors.orEmpty()
                                try {
                                    if (request == 49 && fds.size == 1) {
                                        ParcelFileDescriptor.dup(fds[0]).use { fd ->
                                            // Upstream treats ANY reply as success. On
                                            // failure close without writing a single byte.
                                            if (vpn.protect(fd.fd)) {
                                                socket.outputStream.write(1)
                                                socket.outputStream.flush()
                                            }
                                        }
                                    }
                                } finally {
                                    fds.forEach { runCatching { Os.close(it) } }
                                }
                            }
                        }
                    }
                }, "dppass-bd-protect").apply { isDaemon = true }.start()
                val port = ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { it.localPort }
                val child = ProcessBuilder(listOf(binary.absolutePath, "--ip", "127.0.0.1",
                    "--port", port.toString(), "--protect-path", path.absolutePath, "--no-domain") + strategy)
                    .redirectErrorStream(true).apply { environment()["DPPASS_SOCKS_TOKEN"] = token }.start()
                process = child
                Thread({ runCatching { child.inputStream.use { input ->
                    val buffer = ByteArray(1024)
                    while (input.read(buffer) >= 0) { /* no private traffic logs */ }
                } } }, "dppass-bd-io").apply { isDaemon = true }.start()
                val until = android.os.SystemClock.elapsedRealtime() + 5_000
                while (child.isAlive && android.os.SystemClock.elapsedRealtime() < until) {
                    val ready = runCatching {
                        Socket().use { s ->
                            check(vpn.protect(s))
                            s.connect(InetSocketAddress("127.0.0.1", port), 200)
                            s.soTimeout = 300
                            s.getOutputStream().write(byteArrayOf(5, 1, 2))
                            val input = java.io.DataInputStream(s.getInputStream())
                            check(input.readUnsignedByte() == 5 && input.readUnsignedByte() == 2)
                            val user = "dppass".toByteArray()
                            val pass = token.toByteArray()
                            s.getOutputStream().write(byteArrayOf(1, user.size.toByte()) + user + byteArrayOf(pass.size.toByte()) + pass)
                            input.readUnsignedByte() == 1 && input.readUnsignedByte() == 0
                        }
                    }.getOrDefault(false)
                    if (ready) return ByeDpiRuntime(port, token, child, bound, listener, path)
                    Thread.sleep(40)
                }
                error("Original ByeDPI SOCKS listener did not become ready")
            } catch (e: Exception) {
                process?.destroyForcibly()
                runCatching { server?.close() }
                runCatching { bound.close() }
                path.delete()
                throw e
            }
        }
    }
}
