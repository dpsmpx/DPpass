package com.dpsmpx.dppass.app.alpine

import android.annotation.SuppressLint
import java.io.IOException
import java.util.concurrent.atomic.AtomicBoolean

/**
 * DP_IDE's PTY JNI bridge, adapted to DPpass. These are app-UID processes,
 * not privileged Android processes. PRoot's -0 only fakes guest UID 0.
 */
@SuppressLint("UnsafeDynamicallyLoadedCode")
internal object AlpineNative {
    init {
        System.loadLibrary("dppass-alpine")
    }

    @JvmStatic external fun spawn(
        argv: Array<ByteArray>,
        env: Array<ByteArray>,
        cwd: ByteArray?,
        cols: Int,
        rows: Int,
        fds: IntArray,
    ): Int

    @JvmStatic external fun waitFor(pid: Int): Int

    @JvmStatic external fun kill(pid: Int, signal: Int): Int

    @JvmStatic external fun resize(fd: Int, cols: Int, rows: Int): Int

    @JvmStatic external fun read(fd: Int, buf: ByteArray, off: Int, len: Int): Int

    @JvmStatic external fun write(fd: Int, buf: ByteArray, off: Int, len: Int): Int

    @JvmStatic external fun close(fd: Int): Int

    @JvmStatic external fun describe(errno: Int): String
}

/** Owns a real PTY. No terminal data is logged or persisted. */
internal class AlpineChild private constructor(
    val pid: Int,
    private val writer: Int,
    private val reader: Int,
) {
    private val closed = AtomicBoolean(false)

    fun read(buffer: ByteArray): Int {
        val n = AlpineNative.read(reader, buffer, 0, buffer.size)
        if (n < 0) throw IOException(AlpineNative.describe(-n))
        return n
    }

    @Synchronized
    fun send(bytes: ByteArray) {
        if (closed.get()) return
        val n = AlpineNative.write(writer, bytes, 0, bytes.size)
        if (n < 0) throw IOException(AlpineNative.describe(-n))
    }

    @Synchronized
    fun resize(cols: Int, rows: Int) {
        if (!closed.get()) AlpineNative.resize(reader, cols, rows)
    }

    fun waitFor(): Int = AlpineNative.waitFor(pid)

    fun stop() {
        if (!closed.compareAndSet(false, true)) return
        // The child starts a new session (setsid); stop the whole group.
        AlpineNative.kill(-pid, 15)
        AlpineNative.kill(pid, 15)
        AlpineNative.close(writer)
        AlpineNative.close(reader)
    }

    companion object {
        fun launch(
            argv: List<String>,
            environment: Map<String, String>,
            cols: Int = 80,
            rows: Int = 24,
        ): AlpineChild {
            require(argv.isNotEmpty() && cols in 1..512 && rows in 1..256)
            val fds = IntArray(3)
            val pid = AlpineNative.spawn(
                argv.map { it.toByteArray(Charsets.UTF_8) }.toTypedArray(),
                environment.map { (k, v) -> (k + "=" + v).toByteArray(Charsets.UTF_8) }.toTypedArray(),
                null,
                cols,
                rows,
                fds,
            )
            if (pid < 0) throw IOException("PTY: " + AlpineNative.describe(-pid))
            return AlpineChild(pid, fds[0], fds[1])
        }
    }
}
