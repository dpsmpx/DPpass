package com.dpsmpx.dppass.desktop.ui

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class AppIconTest {
    private fun rgb(size: Int, x: Int, y: Int): Int = AppIcon.image(size).getRGB(x, y)

    @Test
    fun drawingFollowsSvg() {
        // В координатах dppass.svg (128 × 128): фон, обводка, знак и разрыв дуги сверху.
        assertEquals(0, rgb(128, 1, 1) ushr 24, "угол прозрачен")
        assertEquals(0xFF213875.toInt(), rgb(128, 64, 108), "круг — #213875")
        assertEquals(0xFF92B1FF.toInt(), rgb(128, 64, 122), "обводка — #92B1FF")
        assertEquals(0xFFECEEF3.toInt(), rgb(128, 64, 44), "черта — #ECEEF3")
        assertEquals(0xFFECEEF3.toInt(), rgb(128, 64, 94), "большая дуга идёт через низ")
        assertEquals(0xFFECEEF3.toInt(), rgb(128, 34, 64), "дуга слева")
        assertEquals(0xFF213875.toInt(), rgb(128, 53, 35), "сверху между концами дуги — разрыв")
    }

    @Test
    fun everySizeIsSquareAndOpaqueInside() {
        for (size in AppIcon.SIZES) {
            val img = AppIcon.image(size)
            assertEquals(size, img.width)
            assertEquals(size, img.height)
            assertEquals(0xFF, img.getRGB(size / 2, size / 2) ushr 24, "середина значка $size непрозрачна")
        }
        assertFailsWith<IllegalArgumentException> { AppIcon.image(0) }
    }
}
