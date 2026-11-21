package com.dpsmpx.dpai.android.linux

/**
 * JNI ABI imported from DPmetaApp/dpai. The native implementation launches an
 * independent process session with a PTY, reports exec errors and supports
 * resize, signal and close. No Android root privileges are acquired.
 */
internal object NativeCalls {
    init { System.loadLibrary("dpai-native") }

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
