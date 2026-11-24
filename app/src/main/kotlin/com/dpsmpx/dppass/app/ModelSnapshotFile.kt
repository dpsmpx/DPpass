package com.dpsmpx.dppass.app

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Same-directory replacement under the caller's storage lock.
 * Sync the new file before publishing its name. A failure must never
 * acknowledge an unwritten snapshot. Directory fsync is not provided here.
 */
internal object ModelSnapshotFile {
    /** Enforce the actual bytes-read bound, not only a pre-read file size. */
    fun readBounded(source: File, maxBytes: Int): ByteArray? {
        require(maxBytes in 1 until Int.MAX_VALUE)
        return try {
            if (!source.isFile || source.length() !in 1L..maxBytes.toLong()) return null
            source.inputStream().use { input ->
                val buffer = java.io.ByteArrayOutputStream()
                val chunk = ByteArray(minOf(8192, maxBytes + 1))
                var total = 0
                while (total <= maxBytes) {
                    val n = input.read(chunk, 0, minOf(chunk.size, maxBytes + 1 - total))
                    if (n < 0) break
                    if (n == 0) return null
                    total += n
                    if (total > maxBytes) return null
                    buffer.write(chunk, 0, n)
                }
                buffer.toByteArray().takeIf { it.isNotEmpty() }
            }
        } catch (_: IOException) {
            null
        } catch (_: SecurityException) {
            null
        }
    }

    fun replace(dest: File, raw: ByteArray): Boolean {
        val dir = dest.parentFile ?: return false
        var pending: File? = null
        return try {
            if (!dir.isDirectory && !dir.mkdirs() && !dir.isDirectory) return false
            val temp = File.createTempFile(".model-", ".pending", dir)
            pending = temp
            FileOutputStream(temp).use { output ->
                output.write(raw)
                output.fd.sync()
            }
            // Same-filesystem rename; do not remove the old file first.
            temp.renameTo(dest)
        } catch (_: IOException) {
            false
        } catch (_: SecurityException) {
            false
        } finally {
            // Cleanup failure cannot turn an unsuccessful write into success
            // or throw through the Boolean storage API.
            pending?.let { runCatching { it.delete() } }
        }
    }
}
