package com.dpsmpx.dppass.app

import android.content.ContentProvider
import android.content.ContentValues
import android.content.Context
import android.database.Cursor
import android.database.MatrixCursor
import android.net.Uri
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import java.io.File
import java.io.FileNotFoundException

/** Каждая выдача привязана к одному проверенному APK в закрытом кэше. */
class UpdateApkProvider : ContentProvider() {
    companion object {
        internal const val MIME_TYPE = "application/vnd.android.package-archive"
        private val digestPattern = Regex("[0-9a-f]{64}")

        internal fun validDigest(digest: String): Boolean = digestPattern.matches(digest)

        internal fun file(context: Context, digest: String): File {
            require(validDigest(digest))
            return File(context.cacheDir, "updates/$digest.apk")
        }

        internal fun uri(packageName: String, digest: String): Uri {
            require(validDigest(digest))
            return Uri.parse("content://$packageName.updates/apk/$digest.apk")
        }
    }

    override fun onCreate() = true
    private fun checked(request: Uri): File {
        val ctx = context ?: throw FileNotFoundException()
        val digest = digestFor(ctx.packageName, request) ?: throw FileNotFoundException()
        return file(ctx, digest).takeIf { it.isFile } ?: throw FileNotFoundException()
    }

    private fun digestFor(packageName: String, request: Uri): String? {
        val name = request.lastPathSegment ?: return null
        val digest = name.removeSuffix(".apk")
        return digest.takeIf { validDigest(it) && request == uri(packageName, it) }
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException()
        return ParcelFileDescriptor.open(checked(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String? =
        if (context?.let { digestFor(it.packageName, uri) } != null) MIME_TYPE else null

    override fun query(uri: Uri, projection: Array<out String>?, selection: String?,
        selectionArgs: Array<out String>?, sortOrder: String?): Cursor {
        val apk = checked(uri)
        val columns = projection ?: arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE)
        return MatrixCursor(columns).apply {
            addRow(columns.map { column -> when (column) {
                OpenableColumns.DISPLAY_NAME -> "DPpass-update.apk"
                OpenableColumns.SIZE -> apk.length()
                else -> null
            } })
        }
    }

    override fun insert(uri: Uri, values: ContentValues?): Uri? = throw UnsupportedOperationException()
    override fun update(uri: Uri, values: ContentValues?, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
    override fun delete(uri: Uri, selection: String?, selectionArgs: Array<out String>?): Int = throw UnsupportedOperationException()
}
