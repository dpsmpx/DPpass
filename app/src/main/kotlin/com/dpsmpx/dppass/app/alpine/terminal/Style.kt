package com.dpsmpx.dppass.app.alpine.terminal

/**
 * Цвет ячейки (D-71): упакован в 25 бит — 0 — цвет по умолчанию;
 * 1…256 — палитра xterm (индекс + 1); бит 24 — 24-битный RGB.
 */
object TermColor {
    const val DEFAULT: Int = 0
    private const val RGB_FLAG = 1 shl 24

    fun indexed(index: Int): Int {
        require(index in 0..255) { "индекс палитры — 0…255" }
        return index + 1
    }

    fun rgb(r: Int, g: Int, b: Int): Int = RGB_FLAG or ((r and 0xff) shl 16) or ((g and 0xff) shl 8) or (b and 0xff)

    fun isRgb(c: Int): Boolean = c and RGB_FLAG != 0

    fun isIndexed(c: Int): Boolean = c in 1..256

    /** Индекс палитры; для RGB и цвета по умолчанию — -1. */
    fun index(c: Int): Int = if (isIndexed(c)) c - 1 else -1

    /** 0xRRGGBB для RGB; иначе -1. */
    fun rgbValue(c: Int): Int = if (isRgb(c)) c and 0xffffff else -1

    /**
     * Палитра xterm в 0xRRGGBB: 16 основных, куб 6×6×6 и 24 оттенка серого.
     * Основные — свои значения (тёмная тема); куб и серый — формула xterm.
     */
    val PALETTE: IntArray = IntArray(256).also { p ->
        val base = intArrayOf(
            0x000000, 0xcd3131, 0x0dbc79, 0xe5e510, 0x2472c8, 0xbc3fbc, 0x11a8cd, 0xe5e5e5,
            0x666666, 0xf14c4c, 0x23d18b, 0xf5f543, 0x3b8eea, 0xd670d6, 0x29b8db, 0xffffff,
        )
        base.copyInto(p)
        val steps = intArrayOf(0, 95, 135, 175, 215, 255)
        for (i in 0 until 216) p[16 + i] = (steps[i / 36] shl 16) or (steps[(i / 6) % 6] shl 8) or steps[i % 6]
        for (i in 0 until 24) {
            val v = 8 + i * 10
            p[232 + i] = (v shl 16) or (v shl 8) or v
        }
    }
}

/**
 * Стиль ячейки в одном `Long` (память прокрутки назад — тысячи строк):
 * биты 0–24 — цвет текста, 25–49 — фона ([TermColor]), 50 и выше —
 * признаки [Attr].
 */
@JvmInline
value class Style(val bits: Long) {
    val fg: Int get() = (bits and COLOR_MASK).toInt()
    val bg: Int get() = ((bits shr 25) and COLOR_MASK).toInt()

    fun has(attr: Int): Boolean = (bits shr 50) and attr.toLong() != 0L

    fun withFg(c: Int): Style = Style((bits and COLOR_MASK.inv()) or c.toLong())

    fun withBg(c: Int): Style = Style((bits and (COLOR_MASK shl 25).inv()) or (c.toLong() shl 25))

    fun with(attr: Int, on: Boolean): Style =
        Style(if (on) bits or (attr.toLong() shl 50) else bits and (attr.toLong() shl 50).inv())

    companion object {
        private const val COLOR_MASK = (1L shl 25) - 1
        val DEFAULT = Style(0)
    }
}

/** Признаки текста (SGR). */
object Attr {
    const val BOLD = 1
    const val DIM = 2
    const val ITALIC = 4
    const val UNDERLINE = 8
    const val BLINK = 16
    const val INVERSE = 32
    const val INVISIBLE = 64
    const val STRIKE = 128
    const val DOUBLE_UNDERLINE = 256
    const val OVERLINE = 512
}
