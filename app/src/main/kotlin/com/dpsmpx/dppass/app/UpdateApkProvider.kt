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

/** Shares exactly the verified update APK, never arbitrary private paths. */
class UpdateApkProvider : ContentProvider() {
    companion object {
        internal fun file(context: Context) = File(context.cacheDir, "updates/verified.apk")
        internal fun uri(packageName: String): Uri = Uri.parse("content://$packageName.updates/verified.apk")
    }

    override fun onCreate() = true
    private fun checked(request: Uri): File {
        val ctx = context ?: throw FileNotFoundException()
        if (request != uri(ctx.packageName)) throw FileNotFoundException()
        return file(ctx).takeIf { it.isFile } ?: throw FileNotFoundException()
    }

    override fun openFile(uri: Uri, mode: String): ParcelFileDescriptor {
        if (mode != "r") throw FileNotFoundException()
        return ParcelFileDescriptor.open(checked(uri), ParcelFileDescriptor.MODE_READ_ONLY)
    }

    override fun getType(uri: Uri): String? =
        if (context?.let { uri == Companion.uri(it.packageName) } == true) "application/vnd.android.package-archive" else null

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
