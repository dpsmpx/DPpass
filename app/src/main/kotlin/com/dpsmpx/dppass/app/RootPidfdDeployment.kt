package com.dpsmpx.dppass.app

import android.content.Context
import android.os.Build
import java.io.File
import java.io.FileNotFoundException
import java.security.MessageDigest

/** Prepare a verified copy from signed APK assets; no execution as app UID. */
internal object RootPidfdDeployment {
    private val supported = setOf("arm64-v8a", "armeabi-v7a", "x86_64")
    private const val MAX_BYTES = RootPidfdCleanup.MAX_HELPER_BYTES

    data class Staged(val file: File, val digest: String) {
        fun install(directory: String): String = RootPidfdInstall.script(directory, file.absolutePath, digest)
        fun discard() { file.delete() }
    }

    fun stage(context: Context): Staged? {
        val abi = Build.SUPPORTED_ABIS.firstOrNull { it in supported } ?: return null
        val base = "root-pidfd/$abi"
        val digest = try {
            context.assets.open("$base/helper.sha256").use { stream ->
                val bytes = ByteArray(66)
                var size = 0
                while (size < bytes.size) {
                    val n = stream.read(bytes, size, bytes.size - size)
                    if (n < 0) break
                    size += n
                }
                check(size == 65 && bytes[64] == 10.toByte()) { "ROOT: invalid helper digest" }
                bytes.copyOfRange(0, 64).decodeToString()
            }
        } catch (_: FileNotFoundException) {
            // Non-Alpine builds intentionally do not bundle the helper.
            return null
        }
        require(digest.matches(Regex("[0-9a-f]{64}")))
        val staged = File.createTempFile("root-pidfd-", ".bin", context.noBackupFilesDir)
        try {
            val hash = MessageDigest.getInstance("SHA-256")
            var count = 0
            context.assets.open("$base/helper.bin").use { input ->
                staged.outputStream().use { output ->
                    val buffer = ByteArray(8192)
                    while (true) {
                        val n = input.read(buffer)
                        if (n < 0) break
                        count += n
                        check(count <= MAX_BYTES) { "ROOT: helper exceeds size bound" }
                        hash.update(buffer, 0, n)
                        output.write(buffer, 0, n)
                    }
                }
            }
            check(count > 0 && hash.digest().joinToString("") { "%02x".format(it) } == digest) {
                "ROOT: helper checksum mismatch"
            }
            return Staged(staged, digest)
        } catch (failure: Throwable) {
            staged.delete()
            throw failure
        }
    }
}
