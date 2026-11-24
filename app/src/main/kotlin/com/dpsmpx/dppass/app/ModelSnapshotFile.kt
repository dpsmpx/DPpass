package com.dpsmpx.dppass.app

import java.io.File
import java.io.FileOutputStream
import java.io.IOException

/** Same-directory replacement under the caller's storage lock.
 * Sync the new file before publishing its name. A failure must never
 * acknowledge an unwritten snapshot. Directory fsync is not provided here.
 */
internal object ModelSnapshotFile {
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
