package com.dpsmpx.dppass.app.ui

import com.google.zxing.BarcodeFormat
import com.google.zxing.EncodeHintType
import com.google.zxing.qrcode.QRCodeWriter
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** QR камерой (D-71): кадр яркости → текст, размеры кадра и превью, поворот. */
class QrFrameTest {
    private class Frame(val luma: ByteArray, val width: Int, val height: Int, val rowStride: Int)

    /**
     * Кадр камеры [width]×[height] с QR [text] со сдвигом [x], [y]. У строки
     * в памяти — хвост до [rowStride] (мусор, как у камеры), у последней
     * строки хвоста нет. [rotated] — код повёрнут на четверть оборота
     * (камера держится боком). Синтетика, без настоящих серверов.
     */
    private fun frame(
        text: String,
        width: Int = 640,
        height: Int = 480,
        rowStride: Int = 704,
        x: Int = 120,
        y: Int = 60,
        size: Int = 300,
        inverted: Boolean = false,
        rotated: Boolean = false,
    ): Frame {
        val m = QRCodeWriter().encode(text, BarcodeFormat.QR_CODE, size, size, mapOf(EncodeHintType.CHARACTER_SET to "UTF-8"))
        val (ink, paper) = if (inverted) LIGHT to DARK else DARK to LIGHT
        val luma = ByteArray(rowStride * (height - 1) + width) { GARBAGE }
        for (row in 0 until height) for (col in 0 until width) luma[row * rowStride + col] = paper
        for (row in 0 until m.height) {
            for (col in 0 until m.width) {
                val on = if (rotated) m[row, m.width - 1 - col] else m[col, row]
                if (on) luma[(row + y) * rowStride + col + x] = ink
            }
        }
        return Frame(luma, width, height, rowStride)
    }

    private fun decode(f: Frame) = QrFrame.decode(f.luma, f.width, f.height, f.rowStride)

    @Test
    fun codeInAFrameWithPaddedRowsIsRead() {
        val link = "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?type=tcp&security=none#Сервер-1"
        assertEquals(link, decode(frame(link)), "шаг строки больше ширины — хвост строки не часть кадра")
        assertEquals(link, decode(frame(link, rowStride = 640)), "без хвоста")
        val url = "https://sub.example.com/s/synthetic-token"
        assertEquals(url, decode(frame(url, rotated = true)), "камера боком")
        assertEquals(url, decode(frame(url, inverted = true)), "светлый код на тёмном")
    }

    @Test
    fun frameWithoutACodeIsJustNull() {
        val f = frame("https://sub.example.com/s/synthetic-token")
        val blank = ByteArray(f.luma.size) { LIGHT }
        assertNull(QrFrame.decode(blank, f.width, f.height, f.rowStride))
        val noise = Random(7).nextBytes(f.luma.size)
        assertNull(QrFrame.decode(noise, f.width, f.height, f.rowStride))
        assertNull(QrFrame.decode(f.luma, f.width, f.height, f.rowStride) { "   " }, "пустой код — импортировать нечего")
        assertNull(QrFrame.decode(f.luma, f.width, f.height, f.rowStride) { throw ArrayIndexOutOfBoundsException() }, "сбой распознавателя — не падение")
    }

    @Test
    fun frameAndPreviewSizesFitTheLimitsAndShareTheShape() {
        val frames = listOf(FrameSize(4000, 3000), FrameSize(1920, 1080), FrameSize(1280, 720), FrameSize(1024, 768), FrameSize(640, 480))
        val previews = listOf(FrameSize(4000, 3000), FrameSize(1920, 1080), FrameSize(1440, 1080), FrameSize(1280, 720), FrameSize(800, 600))
        val (frame, preview) = QrCameraSizes.choose(frames, previews)!!
        assertEquals(FrameSize(1280, 720), frame, "самый большой кадр в пределе")
        assertEquals(FrameSize(1920, 1080), preview, "превью — того же формата, в своём пределе")

        // Формат кадра 4:3 — и превью 4:3, хотя 16:9 больше.
        val (f43, p43) = QrCameraSizes.choose(listOf(FrameSize(1024, 768)), previews)!!
        assertEquals(FrameSize(1024, 768), f43)
        assertEquals(FrameSize(1440, 1080), p43)

        // Всё больше предела — самое маленькое; камеры без размеров — нет.
        assertEquals(FrameSize(3000, 2000), QrCameraSizes.choose(listOf(FrameSize(4000, 3000), FrameSize(3000, 2000)), previews)!!.first)
        assertNull(QrCameraSizes.choose(emptyList(), previews))
        assertNull(QrCameraSizes.choose(frames, emptyList()))
        assertTrue(FrameSize(1920, 1080).sameShape(FrameSize(1280, 720)))
        assertFalse(FrameSize(1440, 1080).sameShape(FrameSize(1280, 720)))
    }

    @Test
    fun cameraFrameIsSidewaysWhenSensorAndScreenDifferByAQuarterTurn() {
        // Обычный телефон: матрица — 90°, экран стоит — кадр на экране боком.
        assertTrue(QrCameraSizes.swapped(sensorDegrees = 90, displayDegrees = 0))
        assertFalse(QrCameraSizes.swapped(sensorDegrees = 90, displayDegrees = 90), "телефон лёг набок")
        assertTrue(QrCameraSizes.swapped(sensorDegrees = 270, displayDegrees = 180))
        assertFalse(QrCameraSizes.swapped(sensorDegrees = 0, displayDegrees = 0))
        assertTrue(QrCameraSizes.swapped(sensorDegrees = 0, displayDegrees = 270))
    }

    private companion object {
        const val DARK: Byte = 0x10
        const val LIGHT: Byte = 0xF0.toByte()
        const val GARBAGE: Byte = 0x55
    }
}
