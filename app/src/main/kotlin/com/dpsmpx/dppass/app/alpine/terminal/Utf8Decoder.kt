package com.dpsmpx.dppass.app.alpine.terminal

/**
 * Декодер UTF-8 с состоянием между порциями (D-71): вывод по SSH приходит
 * кусками, и символ может разрезаться границей. Неверная
 * последовательность — U+FFFD, а не потеря следующих байтов; избыточная
 * форма и суррогаты — тоже U+FFFD.
 */
class Utf8Decoder {
    private var cp = 0
    private var need = 0
    private var seen = 0
    private var min = 0

    fun decode(bytes: ByteArray, off: Int, len: Int, out: (Int) -> Unit) {
        var i = off
        val end = off + len
        while (i < end) {
            val b = bytes[i].toInt() and 0xff
            if (need == 0) {
                when {
                    b < 0x80 -> out(b)
                    b in 0xC2..0xDF -> start(b and 0x1F, 1, 0x80)
                    b in 0xE0..0xEF -> start(b and 0x0F, 2, 0x800)
                    b in 0xF0..0xF4 -> start(b and 0x07, 3, 0x10000)
                    else -> out(REPLACEMENT)
                }
                i++
            } else if (b and 0xC0 == 0x80) {
                cp = (cp shl 6) or (b and 0x3F)
                seen++
                i++
                if (seen == need) {
                    out(if (cp < min || cp in 0xD800..0xDFFF || cp > 0x10FFFF) REPLACEMENT else cp)
                    need = 0
                }
            } else {
                // Оборванная последовательность: замена, а этот байт — заново как начало.
                need = 0
                out(REPLACEMENT)
            }
        }
    }

    private fun start(bits: Int, n: Int, minimum: Int) {
        cp = bits
        need = n
        seen = 0
        min = minimum
    }

    companion object {
        const val REPLACEMENT = 0xFFFD
    }
}
