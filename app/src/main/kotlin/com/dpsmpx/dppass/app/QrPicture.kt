package com.dpsmpx.dppass.app

import android.content.ContentResolver
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import com.dpsmpx.dppass.app.ui.QrImage
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.FilterInputStream
import java.io.IOException
import java.io.InputStream

/**
 * Картинка с QR (D-65) из выбора файла или «Поделиться»: сначала только
 * размер по заголовку, затем чтение с уменьшением до [QrImage.MAX_PIXELS] и
 * распознавание. Читается не больше [QrImage.MAX_FILE_BYTES]; картинка нигде
 * не сохраняется. Вызывать не на главном потоке.
 */
internal object QrPicture {
    fun read(resolver: ContentResolver, uri: Uri): Outcome<String> {
        val bounds = BitmapFactory.Options().apply { inJustDecodeBounds = true }
        val header = open(resolver, uri) { BitmapFactory.decodeStream(it, null, bounds) }
        if (header.tooLarge) return unreadable(TOO_LARGE)
        if (header.failed || bounds.outWidth <= 0 || bounds.outHeight <= 0) return unreadable(NOT_IMAGE)
        val options = BitmapFactory.Options().apply {
            inSampleSize = QrImage.sampleSize(bounds.outWidth, bounds.outHeight)
            inPreferredConfig = Bitmap.Config.ARGB_8888
        }
        val read = open(resolver, uri) { BitmapFactory.decodeStream(it, null, options) }
        if (read.tooLarge) return unreadable(TOO_LARGE)
        val bitmap = read.value ?: return unreadable(NOT_IMAGE)
        return try {
            val w = bitmap.width
            val h = bitmap.height
            // Декодер уменьшил не так, как просили (не степень двойки у формата): не рисковать памятью.
            if (w.toLong() * h > QrImage.MAX_PIXELS) return unreadable(TOO_LARGE)
            val pixels = IntArray(w * h)
            bitmap.getPixels(pixels, 0, w, 0, 0, w, h)
            QrImage.decode(pixels, w, h)
        } finally {
            bitmap.recycle()
        }
    }

    private class Read<T>(val value: T?, val failed: Boolean, val tooLarge: Boolean)

    private fun <T> open(resolver: ContentResolver, uri: Uri, block: (InputStream) -> T?): Read<T> {
        var limited: Limited? = null
        return try {
            val value = resolver.openInputStream(uri)?.use { block(Limited(it).also { s -> limited = s }) }
            Read(value, failed = limited == null, tooLarge = limited?.exceeded == true)
        } catch (e: IOException) {
            Read(null, failed = true, tooLarge = limited?.exceeded == true)
        } catch (e: SecurityException) {
            Read(null, failed = true, tooLarge = false)
        }
    }

    /** Поток, который после [QrImage.MAX_FILE_BYTES] байт отказывает: картинку больше предела не дочитать. */
    private class Limited(input: InputStream) : FilterInputStream(input) {
        private var count = 0L
        var exceeded = false
            private set

        override fun read(): Int {
            check(1)
            return super.read().also { if (it >= 0) count++ }
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            check(len)
            return super.read(b, off, minOf(len, (QrImage.MAX_FILE_BYTES - count).toInt().coerceAtLeast(1))).also { if (it > 0) count += it }
        }

        override fun skip(n: Long): Long = super.skip(minOf(n, QrImage.MAX_FILE_BYTES - count)).also { count += it }

        private fun check(want: Int) {
            if (want > 0 && count >= QrImage.MAX_FILE_BYTES) {
                exceeded = true
                throw IOException("картинка больше ${QrImage.MAX_FILE_BYTES / (1024 * 1024)} МиБ")
            }
        }
    }

    private fun unreadable(why: String): Outcome<String> = Outcome.failure(DiagCode.IMPORT_IMAGE_UNREADABLE, why)

    private const val NOT_IMAGE = "картинку не прочитать: не изображение или файл повреждён"
    private val TOO_LARGE = "картинка больше ${QrImage.MAX_FILE_BYTES / (1024 * 1024)} МиБ — снимок экрана с QR меньше"
}
