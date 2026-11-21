package com.dpsmpx.dppass.app.alpine.terminal

import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * Рамки и блоки (U+2500–U+259F) — по сетке ячейки, а не глифами шрифта
 * (терминал:A-18): запасной шрифт уже ячейки даёт зазоры в «╭─╮» и «│»,
 * а рамки Claude Code — главная проверка экрана (`docs/DEVICE_CHECK.md`).
 * Так же рисуют kitty, WezTerm и Windows Terminal. Геометрия — здесь, на
 * чистом JVM; холст — у оболочки через [Sink].
 *
 * Линия знака — четыре плеча (вверх, вправо, вниз, влево) с весом:
 * тонкая, толстая или двойная. Плечо идёт от края ячейки к середине и
 * заходит за неё ровно настолько, чтобы стык был без щели; двойная линия —
 * две тонкие, которые у стыка обходят друг друга, как в шрифтах.
 */
object BoxDrawing {
    /** Куда рисует знак: координаты — в пикселях холста. */
    interface Sink {
        /** Прямоугольник цвета знака; [alpha] — доля (тени ░ ▒ ▓). */
        fun rect(l: Float, t: Float, r: Float, b: Float, alpha: Float)

        /** Четверть окружности в овале `l..r × t..b` от угла [startDeg] (0 — вправо, по часовой) линией [stroke]. */
        fun arc(l: Float, t: Float, r: Float, b: Float, startDeg: Float, stroke: Float)

        /** Отрезок линией [stroke] (диагонали ╱ ╲ ╳). */
        fun line(x0: Float, y0: Float, x1: Float, y1: Float, stroke: Float)
    }

    const val NONE = 0
    const val LIGHT = 1
    const val HEAVY = 2
    const val DOUBLE = 3

    private const val UP = 0
    private const val RIGHT = 1
    private const val DOWN = 2
    private const val LEFT = 3

    /**
     * Плечи U+2500–U+257F: четыре цифры «вверх, вправо, вниз, влево» на
     * знак (0 — нет, 1 — тонкое, 2 — толстое, 3 — двойное); по таблице
     * Unicode «Box Drawing». Дуги ╭╮╯╰ — плечами угла, диагонали — нулями.
     */
    private val ARMS: String = listOf(
        "0101 0202 1010 2020 0101 0202 1010 2020 0101 0202 1010 2020 0110 0210 0120 0220", // 2500
        "0011 0012 0021 0022 1100 1200 2100 2200 1001 1002 2001 2002 1110 1210 2110 1120", // 2510
        "2120 2210 1220 2220 1011 1012 2011 1021 2021 2012 1022 2022 0111 0112 0211 0212", // 2520
        "0121 0122 0221 0222 1101 1102 1201 1202 2101 2102 2201 2202 1111 1112 1211 1212", // 2530
        "2111 1121 2121 2112 2211 1122 1221 2212 1222 2122 2221 2222 0101 0202 1010 2020", // 2540
        "0303 3030 0310 0130 0330 0013 0031 0033 1300 3100 3300 1003 3001 3003 1310 3130", // 2550
        "3330 1013 3031 3033 0313 0131 0333 1303 3101 3303 1313 3131 3333 0110 0011 1001", // 2560
        "1100 0000 0000 0000 0001 1000 0100 0010 0002 2000 0200 0020 0201 1020 0102 2010", // 2570
    ).joinToString("").replace(" ", "")

    /** Знак рисуется здесь, а не шрифтом. */
    fun covers(cp: Int): Boolean = cp in 0x2500..0x259F

    /** Плечи знака линии: вверх, вправо, вниз, влево; `null` — не линия. */
    fun arms(cp: Int): IntArray? {
        if (cp !in 0x2500..0x257F) return null
        val i = (cp - 0x2500) * 4
        return IntArray(4) { ARMS[i + it] - '0' }.takeIf { a -> a.any { it != NONE } }
    }

    /** Штрихов на ячейку у пунктира: 2, 3, 4; 0 — сплошная. */
    fun dashes(cp: Int): Int = when (cp) {
        in 0x2504..0x2507 -> 3
        in 0x2508..0x250B -> 4
        in 0x254C..0x254F -> 2
        else -> 0
    }

    /**
     * Толщина тонкой линии в пикселях — от ширины ячейки, то есть от
     * плотности экрана и размера шрифта: на 2,75x и 13 sp — три пикселя.
     */
    fun lightWidth(cellW: Float): Int = max(1, (cellW / 8f).roundToInt())

    /**
     * Нарисовать знак [cp] в ячейке `left, top, w × h` (широкая — `w` двух
     * ячеек) тонкой линией [light] пикселей. `false` — знак не наш, его
     * рисует шрифт.
     */
    fun draw(cp: Int, left: Float, top: Float, w: Float, h: Float, light: Int, sink: Sink): Boolean {
        if (!covers(cp)) return false
        val l = floor(left).toInt()
        val t = floor(top).toInt()
        val r = floor(left + w).toInt()
        val b = floor(top + h).toInt()
        when {
            cp >= 0x2580 -> block(cp, l, t, r, b, sink)
            cp in 0x2571..0x2573 -> diagonal(cp, l, t, r, b, light, sink)
            cp in 0x256D..0x2570 -> arc(cp, l, t, r, b, light, sink)
            else -> lines(arms(cp) ?: return false, dashes(cp), l, t, r, b, light, sink)
        }
        return true
    }

    /** Полоса толщины [w] с серединой [c]: начало (конец — начало + [w]). */
    private fun lo(c: Int, w: Int): Int = c - w / 2

    private fun hi(c: Int, w: Int): Int = lo(c, w) + w

    private fun thick(weight: Int, light: Int): Int = when (weight) {
        LIGHT, DOUBLE -> light
        HEAVY -> light * 2
        else -> 0
    }

    private fun lines(arms: IntArray, dashes: Int, l: Int, t: Int, r: Int, b: Int, light: Int, sink: Sink) {
        val cx = (l + r) / 2
        val cy = (t + b) / 2
        if (dashes > 0) {
            dashed(arms[LEFT] == NONE, thick(arms.max(), light), dashes, l, t, r, b, sink)
            return
        }
        // Половина расстояния между линиями двойной: зазор — в толщину линии.
        val d = light
        for (i in 0 until 4) {
            val weight = arms[i]
            if (weight == NONE) continue
            val vertical = i == UP || i == DOWN
            // Плечо «сверху» или «слева» идёт от меньшей координаты к середине.
            val fromLow = i == UP || i == LEFT
            val along = if (vertical) cy else cx
            val across = if (vertical) cx else cy
            val sideLow = if (vertical) LEFT else UP
            val sideHigh = if (vertical) RIGHT else DOWN
            val opposite = (i + 2) % 4
            if (weight != DOUBLE) {
                val w = thick(weight, light)
                val doubles = (if (arms[sideLow] == DOUBLE) 1 else 0) + (if (arms[sideHigh] == DOUBLE) 1 else 0)
                // Стык закрывает поперечное плечо: его толщина; поперёк пусто — своя.
                val perp = max(thick(arms[sideLow], light), thick(arms[sideHigh], light)).takeIf { it > 0 } ?: w
                // Двойная поперёк насквозь — до ближней её линии; двойная с одной стороны — через обе.
                val end = when (doubles) {
                    2 -> if (fromLow) hi(along - d, light) else lo(along + d, light)
                    1 -> if (fromLow) hi(along + d, light) else lo(along - d, light)
                    else -> if (fromLow) hi(along, perp) else lo(along, perp)
                }
                val a0 = if (fromLow) (if (vertical) t else l) else end
                val a1 = if (fromLow) end else (if (vertical) b else r)
                segment(vertical, a0, a1, lo(across, w), hi(across, w), sink)
                continue
            }
            for ((side, offset) in listOf(sideLow to -d, sideHigh to d)) {
                val other = if (side == sideLow) sideHigh else sideLow
                val single = listOf(side, other, opposite).any { arms[it] == LIGHT || arms[it] == HEAVY }
                // Сдвиг конца от середины к плечу: ближняя линия поперечной двойной, середина или дальняя.
                val stop = when {
                    arms[side] == DOUBLE -> -d
                    arms[opposite] == DOUBLE || single -> 0
                    arms[other] == DOUBLE -> d
                    else -> 0
                }
                val end = if (fromLow) hi(along + stop, light) else lo(along - stop, light)
                val a0 = if (fromLow) (if (vertical) t else l) else end
                val a1 = if (fromLow) end else (if (vertical) b else r)
                segment(vertical, a0, a1, lo(across + offset, light), hi(across + offset, light), sink)
            }
        }
    }

    /** Отрезок плеча: вдоль `a0..a1`, поперёк `c0..c1`. */
    private fun segment(vertical: Boolean, a0: Int, a1: Int, c0: Int, c1: Int, sink: Sink) {
        if (a1 <= a0) return
        if (vertical) sink.rect(c0.toFloat(), a0.toFloat(), c1.toFloat(), a1.toFloat(), 1f) else sink.rect(a0.toFloat(), c0.toFloat(), a1.toFloat(), c1.toFloat(), 1f)
    }

    /**
     * Пунктир ┄ ┆ ┈ ┊ ╌ ╎: [n] штрихов на ячейку, каждый — две трети своей
     * доли с зазорами поровну по краям, чтобы зазор на стыке ячеек был тем же.
     */
    private fun dashed(vertical: Boolean, w: Int, n: Int, l: Int, t: Int, r: Int, b: Int, sink: Sink) {
        val c = if (vertical) (l + r) / 2 else (t + b) / 2
        val a0 = if (vertical) t else l
        val slot = ((if (vertical) b else r) - a0).toFloat() / n
        for (k in 0 until n) {
            val p0 = (a0 + slot * k + slot / 6f).roundToInt().toFloat()
            val p1 = (a0 + slot * (k + 1) - slot / 6f).roundToInt().toFloat()
            if (p1 <= p0) continue
            if (vertical) sink.rect(lo(c, w).toFloat(), p0, hi(c, w).toFloat(), p1, 1f) else sink.rect(p0, lo(c, w).toFloat(), p1, hi(c, w).toFloat(), 1f)
        }
    }

    private fun arc(cp: Int, l: Int, t: Int, r: Int, b: Int, light: Int, sink: Sink) {
        val cx = (l + r) / 2
        val cy = (t + b) / 2
        // Середина линии — как у прямых соседей, чтобы дуга встала в стык.
        val xc = lo(cx, light) + light / 2f
        val yc = lo(cy, light) + light / 2f
        val rad = min(r - l, b - t) / 2f
        val (sx, sy) = when (cp) {
            0x256D -> 1 to 1 // ╭ вниз и вправо
            0x256E -> -1 to 1 // ╮ вниз и влево
            0x256F -> -1 to -1 // ╯ вверх и влево
            else -> 1 to -1 // ╰ вверх и вправо
        }
        val ox = xc + sx * rad
        val oy = yc + sy * rad
        val start = when (cp) {
            0x256D -> 180f
            0x256E -> 270f
            0x256F -> 0f
            else -> 90f
        }
        sink.arc(ox - rad, oy - rad, ox + rad, oy + rad, start, light.toFloat())
        // Остаток до края — прямыми, если ячейка больше дуги.
        val hx = ox.roundToInt()
        if (sx > 0 && hx < r) sink.rect(hx.toFloat(), lo(cy, light).toFloat(), r.toFloat(), hi(cy, light).toFloat(), 1f)
        if (sx < 0 && hx > l) sink.rect(l.toFloat(), lo(cy, light).toFloat(), hx.toFloat(), hi(cy, light).toFloat(), 1f)
        val vy = oy.roundToInt()
        if (sy > 0 && vy < b) sink.rect(lo(cx, light).toFloat(), vy.toFloat(), hi(cx, light).toFloat(), b.toFloat(), 1f)
        if (sy < 0 && vy > t) sink.rect(lo(cx, light).toFloat(), t.toFloat(), hi(cx, light).toFloat(), vy.toFloat(), 1f)
    }

    private fun diagonal(cp: Int, l: Int, t: Int, r: Int, b: Int, light: Int, sink: Sink) {
        val s = light.toFloat()
        if (cp != 0x2572) sink.line(r.toFloat(), t.toFloat(), l.toFloat(), b.toFloat(), s) // ╱
        if (cp != 0x2571) sink.line(l.toFloat(), t.toFloat(), r.toFloat(), b.toFloat(), s) // ╲
    }

    /** Четверти ▖ ▗ ▘ ▙ ▚ ▛ ▜ ▝ ▞ ▟ (U+2596–U+259F): биты — верх-лево 1, верх-право 2, низ-лево 4, низ-право 8. */
    private val QUADRANTS = intArrayOf(4, 8, 1, 13, 9, 7, 11, 2, 6, 14)

    private fun block(cp: Int, l: Int, t: Int, r: Int, b: Int, sink: Sink) {
        val w = r - l
        val h = b - t
        fun y(eighths: Int) = (t + (h * eighths / 8f).roundToInt()).toFloat()
        fun x(eighths: Int) = (l + (w * eighths / 8f).roundToInt()).toFloat()
        val lf = l.toFloat()
        val tf = t.toFloat()
        val rf = r.toFloat()
        val bf = b.toFloat()
        when (cp) {
            0x2580 -> sink.rect(lf, tf, rf, y(4), 1f) // ▀
            in 0x2581..0x2588 -> sink.rect(lf, y(8 - (cp - 0x2580)), rf, bf, 1f) // ▁…█
            in 0x2589..0x258F -> sink.rect(lf, tf, x(0x2590 - cp), bf, 1f) // ▉…▏
            0x2590 -> sink.rect(x(4), tf, rf, bf, 1f) // ▐
            in 0x2591..0x2593 -> sink.rect(lf, tf, rf, bf, (cp - 0x2590) / 4f) // ░ ▒ ▓
            0x2594 -> sink.rect(lf, tf, rf, y(1), 1f) // ▔
            0x2595 -> sink.rect(x(7), tf, rf, bf, 1f) // ▕
            else -> {
                val bits = QUADRANTS[cp - 0x2596]
                if (bits and 1 != 0) sink.rect(lf, tf, x(4), y(4), 1f)
                if (bits and 2 != 0) sink.rect(x(4), tf, rf, y(4), 1f)
                if (bits and 4 != 0) sink.rect(lf, y(4), x(4), bf, 1f)
                if (bits and 8 != 0) sink.rect(x(4), y(4), rf, bf, 1f)
            }
        }
    }
}
