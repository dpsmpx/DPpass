package com.dpsmpx.dppass.app

import android.content.Context
import android.net.LocalServerSocket
import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.os.Process
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import java.io.Closeable
import java.io.File
import java.nio.file.Files

/** Single-use listener in a fresh private cache directory.
 * No abstract namespace, fixed socket reuse, or unbounded accept. */
internal class RootHotspotTunSocket private constructor(
    private val directory: File,
    val path: File,
    private val bound: LocalSocket,
    private val server: LocalServerSocket,
) : Closeable {
    private var accepted = false
    private var closed = false

    fun accept(timeoutMillis: Int = 3_000): LocalSocket {
        require(timeoutMillis in 1..3_000)
        check(!closed && !accepted)
        accepted = true
        // Exactly one consumer. Poll before accept, which has no timeout API.
        val item = StructPollfd().apply {
            fd = server.fileDescriptor
            events = OsConstants.POLLIN.toShort()
        }
        check(Os.poll(arrayOf(item), timeoutMillis) == 1 &&
            item.revents.toInt() and OsConstants.POLLIN != 0) { "ROOT hotspot TUN socket not ready" }
        return server.accept()
    }

    override fun close() {
        if (closed) return
        closed = true
        try {
            server.close()
        } finally {
            try {
                bound.close()
            } finally {
                // Only exact paths created by this endpoint, never recursive.
                path.delete()
                directory.delete()
            }
        }
    }

    companion object {
        fun open(context: Context): RootHotspotTunSocket {
            val directory = Files.createTempDirectory(context.cacheDir.toPath(), "rt-").toFile()
            val path = File(directory, "s")
            var bound: LocalSocket? = null
            try {
                Os.chmod(directory.absolutePath, 448) // 0700
                val stat = Os.lstat(directory.absolutePath)
                check(OsConstants.S_ISDIR(stat.st_mode) && stat.st_uid == Process.myUid() &&
                    stat.st_mode and 511 == 448)
                require(RootHotspotTunLaunch.socketPathValid(path.absolutePath))
                val socket = LocalSocket()
                bound = socket
                socket.bind(LocalSocketAddress(path.absolutePath, LocalSocketAddress.Namespace.FILESYSTEM))
                val server = LocalServerSocket(socket.fileDescriptor)
                return RootHotspotTunSocket(directory, path, socket, server)
            } catch (failure: Throwable) {
                try { bound?.close() } catch (cleanup: Throwable) {
                    if (cleanup !== failure) failure.addSuppressed(cleanup)
                }
                path.delete()
                directory.delete()
                throw failure
            }
        }
    }
}
