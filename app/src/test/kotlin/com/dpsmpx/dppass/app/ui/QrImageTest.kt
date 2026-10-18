package com.dpsmpx.dppass.app.ui

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** QR с картинки (D-65): текст как есть, код на снимке экрана, светлый на тёмном, пределы. */
class QrImageTest {
    private class Picture(val argb: IntArray, val width: Int, val height: Int)

    /** QR с [text] размером [size] на холсте [width]×[height] со сдвигом [x], [y]; синтетика, без настоящих серверов. */
    private fun picture(text: String, size: Int = 240, width: Int = size, height: Int = size, x: Int = 0, y: Int = 0, inverted: Boolean = false): Picture {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8"))
        val (ink, paper) = if (inverted) WHITE to BLACK else BLACK to WHITE
        val px = IntArray(width * height) { paper }
        for (row in 0 until m.height) for (col in 0 until m.width) if (m[col, row]) px[(row + y) * width + col + x] = ink
        return Picture(px, width, height)
    }

    private fun decode(p: Picture) = QrImage.decode(p.argb, p.width, p.height)

    @Test
    fun textComesBackExactlyIncludingUtf8AndLineBreaks() {
        val link = "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?type=tcp&security=none#Сервер-1"
        assertEquals(link, decode(picture(link)).valueOrNull())
        val body = "$link\ntrojan://synthetic-password@203.0.113.11:443#Запасной"
        assertEquals(body, decode(picture(body, size = 320)).valueOrNull())
        val url = "https://sub.example.com/s/synthetic-token"
        assertEquals(url, decode(picture(url)).valueOrNull())
    }

    @Test
    fun codeInsideAScreenshotAndLightOnDarkAreFound() {
        val url = "https://sub.example.com/s/synthetic-token"
        // Снимок экрана 1080×2400 с кодом посередине — целиком, без уменьшения.
        assertEquals(1, QrImage.sampleSize(1080, 2400))
        assertEquals(url, decode(picture(url, size = 420, width = 1080, height = 2400, x = 330, y = 900)).valueOrNull())
        assertEquals(url, decode(picture(url, inverted = true)).valueOrNull(), "светлый код на тёмном фоне (тёмная тема)")
    }

    @Test
    fun noCodeOrEmptyCodeIsNotFound() {
        val blank = Picture(IntArray(300 * 300) { WHITE }, 300, 300)
        val noise = Random(42).let { r -> Picture(IntArray(300 * 300) { if (r.nextBoolean()) BLACK else WHITE }, 300, 300) }
        for (p in listOf(blank, noise, picture("   "))) {
            val f = assertIs<Outcome.Failure>(decode(p))
            assertEquals(DiagCode.IMPORT_QR_NOT_FOUND, f.errors.single().code)
        }
    }

    @Test
    fun sampleSizeKeepsPixelsWithinTheLimit() {
        assertEquals(1, QrImage.sampleSize(2048, 2048))
        assertEquals(2, QrImage.sampleSize(4000, 3000))
        assertEquals(4, QrImage.sampleSize(8000, 6000))
        for ((w, h) in listOf(1 to 1, 1440 to 3200, 4096 to 4096, 1 to 100_000_000, 50_000 to 3, 12_000 to 9_000)) {
            // Как считает декодер с запасом на округление вверх.
            fun pixels(s: Int) = if (s == 1) w.toLong() * h else (w / s + 1).toLong() * (h / s + 1)
            val s = QrImage.sampleSize(w, h)
            assertTrue(s > 0 && s and (s - 1) == 0, "степень двойки: $s")
            assertTrue(pixels(s) <= QrImage.MAX_PIXELS, "$w×$h / $s → ${pixels(s)}")
            if (s > 1) assertTrue(pixels(s / 2) > QrImage.MAX_PIXELS, "не уменьшено лишнего: $w×$h / $s")
        }
    }

    private companion object {
        const val BLACK: Int = 0xFF000000.toInt()
        const val WHITE: Int = 0xFFFFFFFF.toInt()
    }
}
