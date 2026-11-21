package com.dpsmpx.dppass.app.alpine.terminal

/**
 * Что эмулятор отдаёт наружу (D-71): ответы терминала программе (`DA`,
 * `DSR`, отчёты о цветах — в сессию, тем же путём, что ввод), заголовок,
 * звонок, запись в буфер обмена (OSC 52 — экран спрашивает человека).
 */
interface TerminalHost {
    fun write(bytes: ByteArray) {}
    fun title(title: String) {}
    fun bell() {}
    fun clipboard(text: String) {}

    companion object {
        val NONE: TerminalHost = object : TerminalHost {}
    }
}

/** Отслеживание мыши программой (DECSET 1000, 1002, 1003). */
enum class MouseMode { NONE, PRESS, DRAG, ANY }

/**
 * Эмулятор xterm своего терминала (D-71): байты вывода программы →
 * экран. Разбор — машиной состояний ESC/CSI/OSC/DCS; поддержано то, что
 * нужно оболочке, редакторам и интерфейсу Claude Code: курсор и области
 * прокрутки, вставка и удаление, второй экран (1049), цвета 16/256/24 бита,
 * режимы ввода (курсор приложения, вставка в скобках, мышь, фокус),
 * широкие и составные символы, прокрутка назад и перенос строк при смене
 * ширины. Неподдержанное пропускается без следа на экране.
 *
 * Не потокобезопасен: вывод и чтение экрана — под одним замком у
 * вызывающего (сессия терминала).
 */
class TerminalEmulator(
    cols: Int,
    rows: Int,
    private val scrollbackMax: Int = 5_000,
    private val host: TerminalHost = TerminalHost.NONE,
    /** Цвета по умолчанию — для ответов на запросы OSC 10/11 (тема программы). */
    var foregroundRgb: Int = 0xe5e5e5,
    var backgroundRgb: Int = 0x000000,
) {
    var cols: Int = cols
        private set
    var rows: Int = rows
        private set

    private var main = Array(rows) { TerminalRow(cols) }
    private var alt = Array(rows) { TerminalRow(cols) }
    private val history = ArrayDeque<TerminalRow>()
    private var screen = main

    var altScreen: Boolean = false
        private set
    var cursorX: Int = 0
        private set
    var cursorY: Int = 0
        private set
    private var pendingWrap = false
    private var style = Style.DEFAULT
    private var top = 0
    private var bottom = rows - 1
    private var tabs = BooleanArray(cols) { it > 0 && it % 8 == 0 }

    // Режимы.
    var insertMode = false
        private set
    var newLineMode = false
        private set
    var originMode = false
        private set
    var autoWrap = true
        private set
    var cursorKeysApp = false
        private set
    var keypadApp = false
        private set
    var cursorVisible = true
        private set
    var cursorBlink = false
        private set
    /** Вид курсора DECSCUSR: 0–2 — блок, 3–4 — подчёркивание, 5–6 — черта. */
    var cursorShape = 0
        private set
    var reverseVideo = false
        private set
    var bracketedPaste = false
        private set
    var mouseMode = MouseMode.NONE
        private set
    var mouseSgr = false
        private set
    var focusEvents = false
        private set
    /** Синхронный вывод (DECSET 2026): пока включён, экран лучше не перерисовывать. */
    var syncOutput = false
        private set
    var title: String = ""
        private set

    /**
     * Сколько строк всего ушло в прокрутку назад и сколько выпало из её
     * начала: по ним экран держит место чтения, пока идёт вывод (ревью
     * 17 октября 2026). Перестройка при смене размера их не меняет.
     */
    var historyAdded: Long = 0
        private set
    var historyDropped: Long = 0
        private set

    /** Растёт при каждом изменении экрана: экран перерисовывается по нему. */
    var version: Long = 0
        private set

    // Наборы символов: G0, G1 и какой из них в GL (SI/SO).
    private var g0 = Charset.ASCII
    private var g1 = Charset.ASCII
    private var useG1 = false

    private var lastChar = 0

    /** Был ZWJ (U+200D): следующий знак — часть того же эмодзи, в той же ячейке (терминал:A-17). */
    private var joinNext = false

    /** Ссылка OSC 8, открытая программой (терминал:A-19): печатаемые знаки несут её, пока не закрыта. */
    private var hyperlink: String? = null

    private class Saved(val x: Int, val y: Int, val style: Style, val origin: Boolean, val wrap: Boolean, val g0: Charset, val g1: Charset, val useG1: Boolean)

    private var savedMain: Saved? = null
    private var savedAlt: Saved? = null

    // Разбор.
    private enum class State { GROUND, ESCAPE, ESCAPE_INTER, CSI, CSI_IGNORE, OSC, OSC_ESC, STRING, STRING_ESC }

    private var state = State.GROUND
    private val decoder = Utf8Decoder()
    private val intermediates = StringBuilder()
    private var privateMarker = 0
    private val params = ArrayList<IntArray>()
    private var param = -1
    private var subparams = ArrayList<Int>()
    private val osc = StringBuilder()

    private enum class Charset { ASCII, DEC_GRAPHICS }

    init {
        require(cols in 1..MAX_COLS && rows in 1..MAX_ROWS) { "размер терминала — 1…$MAX_COLS × 1…$MAX_ROWS" }
        require(scrollbackMax >= 0) { "прокрутка назад — не отрицательная" }
    }

    // ---- вход ----

    fun feed(bytes: ByteArray, off: Int = 0, len: Int = bytes.size) {
        decoder.decode(bytes, off, len, ::process)
        version++
    }

    /** Для тестов и вставки уже раскодированного текста. */
    fun feed(text: String) {
        text.codePoints().forEach(::process)
        version++
    }

    private fun process(cp: Int) {
        when (state) {
            State.OSC -> {
                when {
                    cp == BEL -> endOsc(bel = true)
                    cp == ESC -> state = State.OSC_ESC
                    cp == ST_C1 -> endOsc(bel = false)
                    osc.length < MAX_OSC -> osc.appendCodePoint(cp)
                }
                return
            }
            State.OSC_ESC -> {
                endOsc(bel = false)
                if (cp != '\\'.code) process2(ESC).also { process(cp) }
                return
            }
            State.STRING -> {
                if (cp == ESC) state = State.STRING_ESC else if (cp == BEL || cp == ST_C1) state = State.GROUND
                return
            }
            State.STRING_ESC -> {
                state = State.GROUND
                if (cp != '\\'.code) process2(ESC).also { process(cp) }
                return
            }
            else -> Unit
        }
        process2(cp)
    }

    private fun process2(cp: Int) {
        if (cp < 0x20 || cp == 0x7f) return control(cp)
        when (state) {
            State.GROUND -> if (cp !in 0x80..0x9f) putChar(cp)
            State.ESCAPE -> escape(cp)
            State.ESCAPE_INTER -> escapeInter(cp)
            State.CSI -> csiChar(cp)
            State.CSI_IGNORE -> if (cp in 0x40..0x7e) state = State.GROUND
            else -> Unit
        }
    }

    private fun control(cp: Int) {
        when (cp) {
            ESC -> {
                state = State.ESCAPE
                intermediates.setLength(0)
            }
            0x18, 0x1a -> state = State.GROUND
            BEL -> host.bell()
            0x08 -> {
                if (cursorX > 0) cursorX--
                pendingWrap = false
            }
            0x09 -> tab(1)
            0x0a, 0x0b, 0x0c -> {
                lineFeed()
                if (newLineMode) cursorX = 0
            }
            0x0d -> {
                cursorX = 0
                pendingWrap = false
            }
            0x0e -> useG1 = true
            0x0f -> useG1 = false
            else -> Unit
        }
    }

    private fun escape(cp: Int) {
        if (cp in 0x20..0x2f) {
            intermediates.appendCodePoint(cp)
            state = State.ESCAPE_INTER
            return
        }
        state = State.GROUND
        // Не ASCII после ESC — не команда: toChar() обрезал бы U+10063 до 'c' (RIS).
        if (cp > 0x7e) {
            if (cp >= 0xa0) putChar(cp)
            return
        }
        when (cp.toChar()) {
            '[' -> {
                state = State.CSI
                params.clear()
                param = -1
                subparams = ArrayList()
                privateMarker = 0
                intermediates.setLength(0)
            }
            ']' -> {
                state = State.OSC
                osc.setLength(0)
            }
            'P', 'X', '^', '_' -> state = State.STRING
            '7' -> saveCursor()
            '8' -> restoreCursor()
            'D' -> lineFeed()
            'E' -> {
                lineFeed()
                cursorX = 0
            }
            'H' -> if (cursorX < cols) tabs[cursorX] = true
            'M' -> reverseIndex()
            'c' -> reset()
            '=' -> keypadApp = true
            '>' -> keypadApp = false
            else -> Unit
        }
    }

    private fun escapeInter(cp: Int) {
        if (cp in 0x20..0x2f) {
            if (intermediates.length < MAX_INTER) intermediates.appendCodePoint(cp)
            return
        }
        state = State.GROUND
        val charset = if (cp == '0'.code) Charset.DEC_GRAPHICS else Charset.ASCII
        when (intermediates.toString()) {
            "(" -> g0 = charset
            ")" -> g1 = charset
            "#" -> if (cp == '8'.code) alignmentTest()
            else -> Unit
        }
    }

    private fun csiChar(cp: Int) {
        when {
            cp in '0'.code..'9'.code -> param = ((if (param < 0) 0 else param) * 10 + (cp - '0'.code)).coerceAtMost(MAX_PARAM)
            cp == ';'.code -> endParam()
            cp == ':'.code -> {
                // Поток без конца не растит память: лишние подпараметры отбрасываются.
                if (subparams.size < MAX_PARAMS) subparams.add(param)
                param = -1
            }
            cp in 0x3c..0x3f -> if (params.isEmpty() && param < 0 && privateMarker == 0) privateMarker = cp else state = State.CSI_IGNORE
            cp in 0x20..0x2f -> if (intermediates.length < MAX_INTER) intermediates.appendCodePoint(cp) else state = State.CSI_IGNORE
            cp in 0x40..0x7e -> {
                endParam()
                state = State.GROUND
                csi(cp.toChar())
            }
            else -> state = State.CSI_IGNORE
        }
    }

    private fun endParam() {
        if (params.size >= MAX_PARAMS) {
            subparams = ArrayList()
            param = -1
            return
        }
        subparams.add(param)
        params.add(subparams.toIntArray())
        subparams = ArrayList()
        param = -1
    }

    /** Параметр [i]: нет или 0 — [def] (как в xterm для счётчиков). */
    private fun p(i: Int, def: Int = 1): Int {
        val v = params.getOrNull(i)?.firstOrNull() ?: -1
        return if (v <= 0) def else v
    }

    /** Параметр [i] как есть: нет — [def] (0 — значимое значение). */
    private fun raw(i: Int, def: Int = 0): Int = params.getOrNull(i)?.firstOrNull()?.takeIf { it >= 0 } ?: def

    private fun csi(final: Char) {
        val inter = intermediates.toString()
        val priv = privateMarker
        when {
            priv == '?'.code && inter.isEmpty() -> when (final) {
                'h' -> for (i in params.indices) decMode(raw(i), true)
                'l' -> for (i in params.indices) decMode(raw(i), false)
                'n' -> if (raw(0) == 6) reply("${ESC_S}[?${cursorRow() + 1};${cursorX + 1}R")
                'J' -> eraseDisplay(raw(0))
                'K' -> eraseLine(raw(0))
                else -> Unit
            }
            priv == '?'.code && inter == "$" && final == 'p' -> reply("${ESC_S}[?${raw(0)};${decModeState(raw(0))}\$y")
            priv == '>'.code && final == 'c' -> reply("${ESC_S}[>1;10;0c")
            priv != 0 -> Unit
            inter == " " && final == 'q' -> {
                cursorShape = raw(0).coerceIn(0, 6)
                cursorBlink = cursorShape == 0 || cursorShape % 2 == 1
            }
            inter == "!" && final == 'p' -> softReset()
            inter.isNotEmpty() -> Unit
            else -> csiPlain(final)
        }
    }

    private fun csiPlain(final: Char) {
        val erase = Style.DEFAULT.withBg(style.bg)
        when (final) {
            '@' -> {
                row().insert(cursorX, p(0), erase)
                pendingWrap = false
            }
            'A' -> moveTo(cursorX, (cursorY - p(0)).coerceAtLeast(if (cursorY >= top) top else 0))
            'B', 'e' -> moveTo(cursorX, (cursorY + p(0)).coerceAtMost(if (cursorY <= bottom) bottom else rows - 1))
            'C', 'a' -> moveTo(cursorX + p(0), cursorY)
            'D' -> moveTo(cursorX - p(0), cursorY)
            'E' -> moveTo(0, (cursorY + p(0)).coerceAtMost(if (cursorY <= bottom) bottom else rows - 1))
            'F' -> moveTo(0, (cursorY - p(0)).coerceAtLeast(if (cursorY >= top) top else 0))
            'G', '`' -> moveTo(p(0) - 1, cursorY)
            'H', 'f' -> setCursor(p(1) - 1, p(0) - 1)
            'I' -> tab(p(0))
            'Z' -> backTab(p(0))
            'J' -> eraseDisplay(raw(0))
            'K' -> eraseLine(raw(0))
            'L' -> if (cursorY in top..bottom) {
                scrollDown(p(0), cursorY)
                cursorX = 0
                pendingWrap = false
            }
            'M' -> if (cursorY in top..bottom) {
                scrollUp(p(0), cursorY, keep = false)
                cursorX = 0
                pendingWrap = false
            }
            'P' -> {
                row().delete(cursorX, p(0), erase)
                pendingWrap = false
            }
            'S' -> scrollUp(p(0), top, keep = true)
            'T' -> if (params.size <= 1) scrollDown(p(0), top)
            'X' -> {
                row().clear(cursorX, cursorX + p(0), erase)
                pendingWrap = false
            }
            'b' -> if (lastChar != 0) repeat(p(0).coerceAtMost(cols * rows)) { putChar(lastChar) }
            'c' -> if (raw(0) == 0) reply("${ESC_S}[?62;22c")
            'd' -> setCursor(cursorX, p(0) - 1)
            'g' -> when (raw(0)) {
                0 -> if (cursorX < cols) tabs[cursorX] = false
                3 -> tabs.fill(false)
            }
            'h', 'l' -> for (i in params.indices) ansiMode(raw(i), final == 'h')
            'm' -> sgr()
            'n' -> when (raw(0)) {
                5 -> reply("${ESC_S}[0n")
                6 -> reply("${ESC_S}[${cursorRow() + 1};${cursorX + 1}R")
            }
            'r' -> {
                val t = p(0) - 1
                // Низ за краем экрана — до края, как в xterm и VTE (размер у программы мог устареть).
                val b = (p(1, rows) - 1).coerceAtMost(rows - 1)
                if (t < b) {
                    top = t
                    bottom = b
                    setCursor(0, 0)
                }
            }
            's' -> saveCursor()
            'u' -> restoreCursor()
            't' -> if (raw(0) == 18) reply("${ESC_S}[8;$rows;${cols}t")
            else -> Unit
        }
    }

    /** Строка курсора относительно области в режиме DECOM (для отчётов). */
    private fun cursorRow(): Int = if (originMode) cursorY - top else cursorY

    private fun ansiMode(mode: Int, on: Boolean) {
        when (mode) {
            4 -> insertMode = on
            20 -> newLineMode = on
        }
    }

    private fun decMode(mode: Int, on: Boolean) {
        when (mode) {
            1 -> cursorKeysApp = on
            5 -> reverseVideo = on
            6 -> {
                originMode = on
                setCursor(0, 0)
            }
            7 -> autoWrap = on
            12 -> cursorBlink = on
            25 -> cursorVisible = on
            47 -> switchScreen(on, clear = false)
            1047 -> switchScreen(on, clear = !on)
            1048 -> if (on) saveCursor() else restoreCursor()
            1049 -> if (on) {
                saveCursor()
                switchScreen(true, clear = true)
            } else {
                switchScreen(false, clear = false)
                restoreCursor()
            }
            9, 1000 -> mouseMode = if (on) MouseMode.PRESS else MouseMode.NONE
            1002 -> mouseMode = if (on) MouseMode.DRAG else MouseMode.NONE
            1003 -> mouseMode = if (on) MouseMode.ANY else MouseMode.NONE
            1006 -> mouseSgr = on
            1004 -> focusEvents = on
            2004 -> bracketedPaste = on
            2026 -> syncOutput = on
        }
    }

    /** DECRQM: 1 — включён, 2 — выключен, 0 — не знаем. */
    private fun decModeState(mode: Int): Int {
        val v: Boolean = when (mode) {
            1 -> cursorKeysApp
            5 -> reverseVideo
            6 -> originMode
            7 -> autoWrap
            12 -> cursorBlink
            25 -> cursorVisible
            47, 1047, 1049 -> altScreen
            1000 -> mouseMode == MouseMode.PRESS
            1002 -> mouseMode == MouseMode.DRAG
            1003 -> mouseMode == MouseMode.ANY
            1004 -> focusEvents
            1006 -> mouseSgr
            2004 -> bracketedPaste
            2026 -> syncOutput
            else -> return 0
        }
        return if (v) 1 else 2
    }

    // ---- SGR ----

    private fun sgr() {
        if (params.isEmpty()) {
            style = Style.DEFAULT
            return
        }
        var i = 0
        while (i < params.size) {
            val group = params[i]
            when (val code = group[0].coerceAtLeast(0)) {
                0 -> style = Style.DEFAULT
                1 -> style = style.with(Attr.BOLD, true)
                2 -> style = style.with(Attr.DIM, true)
                3 -> style = style.with(Attr.ITALIC, true)
                4 -> {
                    val kind = group.getOrNull(1) ?: 1
                    style = style.with(Attr.UNDERLINE, kind != 0 && kind != 2).with(Attr.DOUBLE_UNDERLINE, kind == 2)
                }
                5, 6 -> style = style.with(Attr.BLINK, true)
                7 -> style = style.with(Attr.INVERSE, true)
                8 -> style = style.with(Attr.INVISIBLE, true)
                9 -> style = style.with(Attr.STRIKE, true)
                21 -> style = style.with(Attr.DOUBLE_UNDERLINE, true)
                22 -> style = style.with(Attr.BOLD, false).with(Attr.DIM, false)
                23 -> style = style.with(Attr.ITALIC, false)
                24 -> style = style.with(Attr.UNDERLINE, false).with(Attr.DOUBLE_UNDERLINE, false)
                25 -> style = style.with(Attr.BLINK, false)
                27 -> style = style.with(Attr.INVERSE, false)
                28 -> style = style.with(Attr.INVISIBLE, false)
                29 -> style = style.with(Attr.STRIKE, false)
                in 30..37 -> style = style.withFg(TermColor.indexed(code - 30))
                38, 48, 58 -> {
                    val (color, used) = extendedColor(i)
                    if (color != null) {
                        if (code == 38) style = style.withFg(color) else if (code == 48) style = style.withBg(color)
                    }
                    i += used
                }
                39 -> style = style.withFg(TermColor.DEFAULT)
                in 40..47 -> style = style.withBg(TermColor.indexed(code - 40))
                49 -> style = style.withBg(TermColor.DEFAULT)
                53 -> style = style.with(Attr.OVERLINE, true)
                55 -> style = style.with(Attr.OVERLINE, false)
                in 90..97 -> style = style.withFg(TermColor.indexed(code - 90 + 8))
                in 100..107 -> style = style.withBg(TermColor.indexed(code - 100 + 8))
                else -> Unit
            }
            i++
        }
    }

    /**
     * Цвет 38/48 в двух записях: через `:` в одной группе (`38:5:n`,
     * `38:2::r:g:b`, `38:2:r:g:b`) и через `;` (`38;5;n`, `38;2;r;g;b`).
     * Итог — цвет и сколько групп `;` занято сверх первой.
     */
    private fun extendedColor(i: Int): Pair<Int?, Int> {
        val g = params[i]
        if (g.size > 1) {
            return when (g[1]) {
                5 -> (g.getOrNull(2)?.takeIf { it in 0..255 }?.let(TermColor::indexed)) to 0
                2 -> {
                    val rgb = if (g.size >= 6) g.copyOfRange(3, 6) else g.copyOfRange(2, minOf(5, g.size))
                    (if (rgb.size == 3 && rgb.all { it in 0..255 }) TermColor.rgb(rgb[0], rgb[1], rgb[2]) else null) to 0
                }
                else -> null to 0
            }
        }
        fun at(k: Int) = params.getOrNull(i + k)?.firstOrNull() ?: -1
        return when (at(1)) {
            5 -> (at(2).takeIf { it in 0..255 }?.let(TermColor::indexed)) to 2
            2 -> {
                val r = at(2)
                val gg = at(3)
                val b = at(4)
                (if (r in 0..255 && gg in 0..255 && b in 0..255) TermColor.rgb(r, gg, b) else null) to 4
            }
            else -> null to 0
        }
    }

    // ---- OSC ----

    private fun endOsc(bel: Boolean) {
        state = State.GROUND
        val s = osc.toString()
        val sep = s.indexOf(';')
        val code = (if (sep < 0) s else s.substring(0, sep)).toIntOrNull() ?: return
        val arg = if (sep < 0) "" else s.substring(sep + 1)
        val end = if (bel) "\u0007" else "${ESC_S}\\"
        when (code) {
            0, 2 -> {
                title = arg.take(MAX_TITLE)
                host.title(title)
            }
            4 -> {
                val parts = arg.split(';')
                var k = 0
                while (k + 1 < parts.size) {
                    val idx = parts[k].toIntOrNull()
                    if (idx != null && idx in 0..255 && parts[k + 1] == "?") reply("${ESC_S}]4;$idx;${rgbSpec(TermColor.PALETTE[idx])}$end")
                    k += 2
                }
            }
            // OSC 8 ; параметры ; адрес — ссылка у следующих знаков; пустой адрес закрывает (терминал:A-19).
            // Только http(s) и не длиннее предела: `intent:`, `file:` программа на target не подсунет.
            8 -> hyperlink = arg.substringAfter(';', "").takeIf { it.length <= MAX_LINK && LINK_SCHEME.matches(it) }
            // OSC 9 и 777;notify — уведомление программы (терминал:A-8): как звонок, без текста (T8).
            // Уведомление программы — `9;<текст>`; служебные формы ConEmu и Windows Terminal (`9;4;…` — ход,
            // `9;9;<каталог>` — каталог у каждого приглашения) — не сигнал, как в ghostty.
            9 -> if (!OSC9_SERVICE.containsMatchIn(arg)) host.bell()
            777 -> if (arg.startsWith("notify")) host.bell()
            10 -> if (arg == "?") reply("${ESC_S}]10;${rgbSpec(foregroundRgb)}$end")
            11 -> if (arg == "?") reply("${ESC_S}]11;${rgbSpec(backgroundRgb)}$end")
            52 -> {
                // Только запись: чтение буфера обмена программой — утечка (содержимое не отдаём).
                val data = arg.substringAfter(';', "")
                if (data != "?" && data.isNotEmpty()) {
                    runCatching { String(java.util.Base64.getDecoder().decode(data), Charsets.UTF_8) }.getOrNull()?.let(host::clipboard)
                }
            }
            else -> Unit
        }
    }

    private fun rgbSpec(rgb: Int): String {
        fun c(v: Int) = "%02x%02x".format(v, v)
        return "rgb:${c(rgb shr 16 and 0xff)}/${c(rgb shr 8 and 0xff)}/${c(rgb and 0xff)}"
    }

    private fun reply(s: String) = host.write(s.toByteArray(Charsets.UTF_8))

    // ---- печать ----

    private fun row(): TerminalRow = screen[cursorY]

    private fun putChar(input: Int) {
        val cp = if ((if (useG1) g1 else g0) == Charset.DEC_GRAPHICS) decGraphics(input) else input
        val w = CharWidth.of(cp)
        if (w == 0) {
            combineWithPrevious(cp)
            return
        }
        // Эмодзи-кластеры (терминал:A-17): знак после ZWJ и вторая буква флага — в ту же ячейку, ширина 2.
        val prev = previousCell()
        val r0 = row()
        if (joinNext) {
            joinNext = false
            if (prev >= 0 && r0.codePoint(prev) != TerminalRow.EMPTY) {
                r0.combine(prev, cp)
                widen(prev)
                return
            }
        }
        if (CharWidth.regional(cp) && prev >= 0 && CharWidth.regional(r0.codePoint(prev)) && r0.combiningAt(prev) == null) {
            r0.combine(prev, cp)
            widen(prev)
            return
        }
        if (pendingWrap) {
            if (autoWrap) {
                row().wrapped = true
                cursorX = 0
                lineFeed()
            }
            pendingWrap = false
        }
        if (w == 2 && cursorX == cols - 1) {
            if (cols < 2) return
            if (autoWrap) {
                row().clear(cursorX, cols, Style.DEFAULT.withBg(style.bg))
                row().wrapped = true
                cursorX = 0
                lineFeed()
            } else {
                cursorX = cols - 2
            }
        }
        val r = row()
        if (insertMode) r.insert(cursorX, w, Style.DEFAULT.withBg(style.bg))
        clearWideAround(r, cursorX, w)
        r.set(cursorX, cp, style)
        if (w == 2) r.set(cursorX + 1, TerminalRow.WIDE_TAIL, style)
        hyperlink?.let { url ->
            r.setLink(cursorX, url)
            if (w == 2) r.setLink(cursorX + 1, url)
        }
        lastChar = cp
        cursorX += w
        if (cursorX >= cols) {
            cursorX = cols - 1
            pendingWrap = autoWrap
        }
    }

    /** Запись поверх половины широкого символа стирает и вторую половину. */
    private fun clearWideAround(r: TerminalRow, x: Int, w: Int) {
        if (r.codePoint(x) == TerminalRow.WIDE_TAIL && x > 0) r.set(x - 1, TerminalRow.EMPTY, r.style(x - 1))
        val end = x + w
        if (end < cols && r.codePoint(end) == TerminalRow.WIDE_TAIL) r.set(end, TerminalRow.EMPTY, r.style(end))
    }

    private fun combineWithPrevious(cp: Int) {
        val r = row()
        val x = previousCell()
        if (x < 0 || r.codePoint(x) == TerminalRow.EMPTY) return
        r.combine(x, cp)
        when (cp) {
            // VS16 — вид эмодзи: знак шириной 1 становится шириной 2 (терминал:A-17).
            0xFE0F -> if (CharWidth.emojiCapable(r.codePoint(x))) widen(x)
            ZWJ -> joinNext = true
        }
    }

    /** Ячейка последнего знака: с учётом ожидающего переноса и правой половины широкого; нет — -1. */
    private fun previousCell(): Int {
        val r = row()
        var x = if (pendingWrap) cursorX else cursorX - 1
        if (x < 0) return -1
        if (r.codePoint(x) == TerminalRow.WIDE_TAIL && x > 0) x--
        return x
    }

    /**
     * Знак в ячейке [x] стал шириной 2: правая половина — следующая ячейка,
     * курсор — за ней. У края строки не расширяется (как у xterm: знак
     * остаётся в одной ячейке, а не переносится задним числом).
     */
    private fun widen(x: Int) {
        val r = row()
        if (x + 1 >= cols || r.codePoint(x + 1) == TerminalRow.WIDE_TAIL) return
        clearWideAround(r, x + 1, 1)
        r.set(x + 1, TerminalRow.WIDE_TAIL, r.style(x))
        if (!pendingWrap && cursorX == x + 1) {
            cursorX = x + 2
            if (cursorX >= cols) {
                cursorX = cols - 1
                pendingWrap = autoWrap
            }
        }
    }

    private fun decGraphics(cp: Int): Int = if (cp >= 0x80) cp else when (cp.toChar()) {
        'j' -> 0x2518
        'k' -> 0x2510
        'l' -> 0x250C
        'm' -> 0x2514
        'n' -> 0x253C
        'q' -> 0x2500
        't' -> 0x251C
        'u' -> 0x2524
        'v' -> 0x2534
        'w' -> 0x252C
        'x' -> 0x2502
        'a' -> 0x2592
        '`' -> 0x25C6
        'f' -> 0x00B0
        'g' -> 0x00B1
        'y' -> 0x2264
        'z' -> 0x2265
        '~' -> 0x00B7
        else -> cp
    }

    // ---- курсор и прокрутка ----

    private fun moveTo(x: Int, y: Int) {
        cursorX = x.coerceIn(0, cols - 1)
        cursorY = y.coerceIn(0, rows - 1)
        pendingWrap = false
    }

    /** CUP: в режиме DECOM — относительно области прокрутки и внутри неё. */
    private fun setCursor(x: Int, y: Int) {
        if (originMode) moveTo(x, (y + top).coerceIn(top, bottom)) else moveTo(x, y)
    }

    private fun lineFeed() {
        pendingWrap = false
        if (cursorY == bottom) scrollUp(1, top, keep = true) else if (cursorY < rows - 1) cursorY++
    }

    private fun reverseIndex() {
        pendingWrap = false
        if (cursorY == top) scrollDown(1, top) else if (cursorY > 0) cursorY--
    }

    /**
     * Сдвиг строк [from]…[bottom] вверх на [n]. [keep] — уходящие строки
     * основного экрана — в прокрутку назад (как xterm: только если область
     * начинается сверху).
     */
    private fun scrollUp(n: Int, from: Int, keep: Boolean) {
        val k = n.coerceAtMost(bottom - from + 1)
        if (k <= 0) return
        val erase = Style.DEFAULT.withBg(style.bg)
        for (i in 0 until k) {
            val gone = screen[from]
            if (keep && !altScreen && from == 0 && scrollbackMax > 0) {
                history.addLast(gone)
                historyAdded++
                if (history.size > scrollbackMax) {
                    history.removeFirst()
                    historyDropped++
                }
            }
            for (y in from until bottom) screen[y] = screen[y + 1]
            screen[bottom] = TerminalRow(cols).also { it.clear(0, cols, erase) }
        }
    }

    private fun scrollDown(n: Int, from: Int) {
        val k = n.coerceAtMost(bottom - from + 1)
        if (k <= 0) return
        val erase = Style.DEFAULT.withBg(style.bg)
        for (i in 0 until k) {
            for (y in bottom downTo from + 1) screen[y] = screen[y - 1]
            screen[from] = TerminalRow(cols).also { it.clear(0, cols, erase) }
        }
    }

    private fun tab(n: Int) {
        repeat(n) {
            var x = cursorX + 1
            while (x < cols - 1 && !tabs[x]) x++
            cursorX = x.coerceAtMost(cols - 1)
        }
        pendingWrap = false
    }

    private fun backTab(n: Int) {
        repeat(n) {
            var x = cursorX - 1
            while (x > 0 && !tabs[x]) x--
            cursorX = x.coerceAtLeast(0)
        }
        pendingWrap = false
    }

    private fun eraseDisplay(mode: Int) {
        val erase = Style.DEFAULT.withBg(style.bg)
        when (mode) {
            // Стёртый конец строки — конец мягкого переноса (как ClearRight в xterm): иначе смена
            // размера склеит строку со следующей, а копирование потеряет перевод строки.
            0 -> {
                screen[cursorY].clear(cursorX, cols, erase)
                screen[cursorY].wrapped = false
                for (y in cursorY + 1 until rows) screen[y].also { it.clear(0, cols, erase); it.wrapped = false }
            }
            1 -> {
                for (y in 0 until cursorY) screen[y].also { it.clear(0, cols, erase); it.wrapped = false }
                screen[cursorY].clear(0, cursorX + 1, erase)
            }
            2 -> for (y in 0 until rows) screen[y].also { it.clear(0, cols, erase); it.wrapped = false }
            3 -> {
                historyDropped += history.size
                history.clear()
            }
        }
        pendingWrap = false
    }

    private fun eraseLine(mode: Int) {
        val erase = Style.DEFAULT.withBg(style.bg)
        when (mode) {
            0 -> row().also { it.clear(cursorX, cols, erase); it.wrapped = false }
            1 -> row().clear(0, cursorX + 1, erase)
            2 -> row().also { it.clear(0, cols, erase); it.wrapped = false }
        }
        pendingWrap = false
    }

    private fun alignmentTest() {
        for (y in 0 until rows) for (x in 0 until cols) screen[y].set(x, 'E'.code, Style.DEFAULT)
        top = 0
        bottom = rows - 1
        moveTo(0, 0)
    }

    private fun saveCursor() {
        val s = Saved(cursorX, cursorY, style, originMode, pendingWrap, g0, g1, useG1)
        if (altScreen) savedAlt = s else savedMain = s
    }

    private fun restoreCursor() {
        val s = (if (altScreen) savedAlt else savedMain) ?: Saved(0, 0, Style.DEFAULT, false, false, Charset.ASCII, Charset.ASCII, false)
        cursorX = s.x.coerceIn(0, cols - 1)
        cursorY = s.y.coerceIn(0, rows - 1)
        style = s.style
        originMode = s.origin
        pendingWrap = s.wrap
        g0 = s.g0
        g1 = s.g1
        useG1 = s.useG1
    }

    private fun switchScreen(toAlt: Boolean, clear: Boolean) {
        if (toAlt == altScreen) {
            if (toAlt && clear) eraseDisplay(2)
            return
        }
        if (toAlt) {
            altScreen = true
            screen = alt
            if (clear) for (r in alt) r.also { it.clear(0, cols, Style.DEFAULT); it.wrapped = false }
        } else {
            if (clear) for (r in alt) r.clear(0, cols, Style.DEFAULT)
            altScreen = false
            screen = main
        }
        pendingWrap = false
    }

    private fun softReset() {
        insertMode = false
        originMode = false
        autoWrap = true
        cursorKeysApp = false
        keypadApp = false
        cursorVisible = true
        style = Style.DEFAULT
        top = 0
        bottom = rows - 1
        g0 = Charset.ASCII
        g1 = Charset.ASCII
        useG1 = false
        savedMain = null
        savedAlt = null
    }

    /** RIS: всё в исходное состояние, прокрутка назад сохраняется. */
    fun reset() {
        hyperlink = null
        joinNext = false
        softReset()
        newLineMode = false
        reverseVideo = false
        bracketedPaste = false
        mouseMode = MouseMode.NONE
        mouseSgr = false
        focusEvents = false
        syncOutput = false
        cursorBlink = false
        cursorShape = 0
        if (altScreen) switchScreen(false, clear = true)
        for (r in main) r.also { it.clear(0, cols, Style.DEFAULT); it.wrapped = false }
        tabs = BooleanArray(cols) { it > 0 && it % 8 == 0 }
        moveTo(0, 0)
        state = State.GROUND
        version++
    }

    // ---- размер ----

    /**
     * Новый размер. Основной экран собирается заново по мягким переносам
     * ([TerminalRow.wrapped]): строка, перенесённая по ширине, при смене
     * ширины снова одна; курсор остаётся у того же символа. Второй экран
     * (полноэкранные программы) обрезается и дополняется: программа
     * перерисует его по SIGWINCH.
     */
    fun resize(newCols: Int, newRows: Int) {
        require(newCols in 1..MAX_COLS && newRows in 1..MAX_ROWS) { "размер терминала — 1…$MAX_COLS × 1…$MAX_ROWS" }
        if (newCols == cols && newRows == rows) return
        // Курсор основного экрана, который надо провести через перестройку: текущий, а во втором
        // экране — сохранённый 1049, на него вернётся оболочка. Отложенный перенос — столбец за краем.
        val mainCursor: Pair<Int, Int>? = if (!altScreen) {
            history.size + cursorY to cursorX + (if (pendingWrap) 1 else 0)
        } else {
            savedMain?.let { history.size + it.y to it.x + (if (it.wrap) 1 else 0) }
        }
        val (newMain, cursor) = reflow(main, newCols, newRows, mainCursor)
        main = newMain
        alt = Array(newRows) { y -> (alt.getOrNull(y) ?: TerminalRow(newCols)).also { it.resize(newCols) } }
        cols = newCols
        rows = newRows
        screen = if (altScreen) alt else main
        top = 0
        bottom = rows - 1
        tabs = BooleanArray(cols) { it > 0 && it % 8 == 0 }
        fun clamp(it: Saved) = Saved(it.x.coerceIn(0, cols - 1), it.y.coerceIn(0, rows - 1), it.style, it.origin, false, it.g0, it.g1, it.useG1)
        if (altScreen) {
            moveTo(cursorX, cursorY)
            savedMain = savedMain?.let {
                if (cursor == null) clamp(it) else Saved(cursor.second.coerceIn(0, cols - 1), cursor.first.coerceIn(0, rows - 1), it.style, it.origin, cursor.second >= cols, it.g0, it.g1, it.useG1)
            }
        } else {
            if (cursor != null) {
                cursorX = cursor.second.coerceIn(0, cols - 1)
                cursorY = cursor.first.coerceIn(0, rows - 1)
            }
            pendingWrap = cursor != null && cursor.second >= cols && autoWrap
            savedMain = savedMain?.let(::clamp)
        }
        savedAlt = savedAlt?.let(::clamp)
        version++
    }

    private class Cell(val cp: Int, val style: Long, val combining: String?, val link: String? = null)

    /** Перестройка истории и основного экрана; итог — экран и новое место курсора (строка экрана, столбец). */
    private fun reflow(screenRows: Array<TerminalRow>, newCols: Int, newRows: Int, cursor: Pair<Int, Int>?): Pair<Array<TerminalRow>, Pair<Int, Int>?> {
        val all = ArrayList<TerminalRow>(history.size + screenRows.size).apply { addAll(history); addAll(screenRows) }
        // Пустые строки под курсором (и под последней непустой) — не содержимое.
        var last = all.size - 1
        val keepTo = cursor?.first ?: -1
        while (last > keepTo && all[last].used() == 0 && !all[last].wrapped) last--
        val out = ArrayList<TerminalRow>()
        var newCursor: Pair<Int, Int>? = null
        var i = 0
        while (i <= last) {
            // Логическая строка: подряд строки с мягким переносом.
            val cells = ArrayList<Cell>()
            var cursorOffset = -1
            while (true) {
                val r = all[i]
                // Пустой хвост перенесённой строки — отступ перед широким символом, не содержимое.
                val width = r.used()
                if (cursor != null && i == cursor.first) {
                    // Номер ячейки курсора в логической строке: правые половины широких — не ячейки.
                    var idx = cells.size
                    for (c in 0 until minOf(cursor.second, width)) if (r.codePoint(c) != TerminalRow.WIDE_TAIL) idx++
                    cursorOffset = idx + (cursor.second - width).coerceAtLeast(0)
                }
                for (c in 0 until width) {
                    val cp = r.codePoint(c)
                    if (cp == TerminalRow.WIDE_TAIL) continue
                    cells += Cell(cp, r.styles[c], r.combiningAt(c), r.linkAt(c))
                }
                if (!r.wrapped || i == last) break
                i++
            }
            i++
            // Раскладка по новой ширине.
            val startRow = out.size
            var row = TerminalRow(newCols)
            var x = 0
            var cursorPlaced = false
            fun placeCursorIfHere(cellIndex: Int) {
                if (!cursorPlaced && cursorOffset >= 0 && cellIndex >= cursorOffset) {
                    newCursor = out.size to x
                    cursorPlaced = true
                }
            }
            for ((k, cell) in cells.withIndex()) {
                // Широкий знак в один столбец не входит: занимает одну ячейку, без правой половины.
                val wide = cell.cp != TerminalRow.EMPTY && CharWidth.cluster(cell.cp, cell.combining) == 2 && newCols >= 2
                val w = if (wide) 2 else 1
                if (x + w > newCols) {
                    row.wrapped = true
                    out += row
                    row = TerminalRow(newCols)
                    x = 0
                }
                placeCursorIfHere(k)
                row.set(x, cell.cp, Style(cell.style))
                cell.combining?.codePoints()?.forEach { row.combine(x, it) }
                row.setLink(x, cell.link)
                if (wide) {
                    row.set(x + 1, TerminalRow.WIDE_TAIL, Style(cell.style))
                    row.setLink(x + 1, cell.link)
                }
                x += w
            }
            if (!cursorPlaced && cursorOffset >= 0) {
                // Курсор за последним символом: столбец — отступ от начала логической строки.
                val extra = cursorOffset - cells.size
                var cx = x + extra
                // Ровно за последним символом во всю ширину — отложенный перенос: тот же ряд, столбец newCols.
                while (cx > newCols || (cx == newCols && extra > 0)) {
                    row.wrapped = true
                    out += row
                    row = TerminalRow(newCols)
                    cx -= newCols
                }
                newCursor = out.size to cx
            }
            out += row
            if (out.size == startRow) out += TerminalRow(newCols)
        }
        // Курсор ниже всего содержимого (пустые строки внизу экрана).
        if (cursor != null && newCursor == null) newCursor = out.size to cursor.second.coerceAtMost(newCols - 1)
        val cursorLine = newCursor?.first ?: (out.size - 1)
        while (out.size <= cursorLine) out += TerminalRow(newCols)
        // Окно экрана: последние строки, но курсор — на экране.
        val end = maxOf(out.size, cursorLine + 1)
        // Строк под курсором больше, чем рядов, — лишние нижние уходят, а не строка курсора в историю.
        val start = (end - newRows).coerceAtLeast(0).let { if (cursor != null) minOf(it, cursorLine) else it }
        history.clear()
        for (k in 0 until start) history.addLast(out[k])
        while (history.size > scrollbackMax) history.removeFirst()
        val screenOut = Array(newRows) { y -> out.getOrNull(start + y) ?: TerminalRow(newCols) }
        return screenOut to newCursor?.let { (it.first - start) to it.second }
    }

    // ---- чтение экрана ----

    /** Строка экрана [y] (0 — верхняя) активного экрана. */
    fun screenRow(y: Int): TerminalRow = screen[y]

    val scrollbackSize: Int get() = history.size

    /** Строка прокрутки назад [i]: 0 — самая старая. */
    fun scrollbackRow(i: Int): TerminalRow = history[i]

    /** Строка по сквозному номеру: сначала прокрутка назад, затем экран. */
    fun line(index: Int): TerminalRow = if (index < history.size) history[index] else screen[index - history.size]

    val lineCount: Int get() = history.size + rows

    /** Текст экрана: строки без пустого хвоста, через `\n`. */
    fun screenText(): String = (0 until rows).joinToString("\n") { screen[it].text() }.trimEnd('\n')

    /**
     * Ссылка `http(s)://` под ячейкой ([line] — сквозной номер, [col] —
     * столбец) или `null`. Логическая строка собирается из мягких
     * переносов: длинный адрес входа Claude (`/login`) переносится по
     * ширине экрана. Другие схемы (`intent:`, `file:`) не ссылки — их
     * программа на target могла бы подсунуть.
     */
    /**
     * Какие ячейки строки [line] — ссылка (терминал:A-19): OSC 8 и найденные
     * адреса `http(s)` логической строки; экран их подчёркивает. Один разбор
     * на строку, а не на ячейку.
     */
    /** Найденное поиском: строка (сквозной номер) и столбцы совпадения. */
    data class Match(val line: Int, val cols: IntRange)

    /**
     * Поиск по истории и экрану (терминал:A-4): без регистра, по строкам;
     * [up] — к старым, от строки перед [from], иначе — к новым, от строки
     * после [from]; нет — `null`. Совпадение — столбцами, для подсветки.
     */
    fun find(query: String, from: Int, up: Boolean): Match? {
        if (query.isEmpty()) return null
        val range = if (up) (minOf(from, lineCount) - 1) downTo 0 else (maxOf(from, -1) + 1) until lineCount
        for (l in range) {
            val r = line(l)
            val text = StringBuilder()
            val colOf = IntArray(r.cols * 2 + 8)
            var n = 0
            for (c in 0 until r.cols) {
                val piece = r.text(c)
                for (ch in piece) {
                    if (n >= colOf.size) break
                    colOf[n++] = c
                    text.append(ch)
                }
            }
            val at = text.indexOf(query, ignoreCase = true)
            if (at >= 0) {
                val end = at + query.length - 1
                return Match(l, colOf[at]..colOf[end.coerceAtMost(n - 1)])
            }
        }
        return null
    }

    fun linkCells(line: Int): BooleanArray = linkCells(lineCount, ::line, line)

    fun linkAt(line: Int, col: Int): String? {
        if (line !in 0 until lineCount) return null
        // Правая половина широкого знака — тот же знак: иначе касание попадало бы в следующую ячейку.
        val cell = if (col > 0 && col < line(line).cols && line(line).codePoint(col) == TerminalRow.WIDE_TAIL) col - 1 else col
        // Ссылка OSC 8 у ячейки — первой: её адрес назвала программа (терминал:A-19).
        if (cell in 0 until line(line).cols) line(line).linkAt(cell)?.let { return it }
        var first = line
        while (first > 0 && line(first - 1).wrapped) first--
        var last = line
        while (last < lineCount - 1 && line(last).wrapped) last++
        val text = StringBuilder()
        var at = -1
        for (l in first..last) {
            val r = line(l)
            for (c in 0 until r.cols) {
                if (l == line && c == cell) at = text.length
                text.append(r.text(c))
            }
        }
        if (at < 0) return null
        for (m in LINK.findAll(text)) {
            val url = m.value.trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '»', '"', '\'')
            if (at >= m.range.first && at < m.range.first + url.length) return url
        }
        return null
    }

    /**
     * Текст выделения по сквозным номерам строк: от ([fromLine], [fromCol])
     * до ([toLine], [toCol]) включительно; мягкий перенос — без `\n`.
     */
    fun text(fromLine: Int, fromCol: Int, toLine: Int, toCol: Int): String = buildString {
        for (l in fromLine..toLine.coerceAtMost(lineCount - 1)) {
            val r = line(l)
            val a = if (l == fromLine) fromCol.coerceIn(0, r.cols) else 0
            val b = if (l == toLine) (toCol + 1).coerceIn(a, r.cols) else r.cols
            val piece = StringBuilder()
            for (c in a until b) piece.append(r.text(c))
            append(if (r.wrapped && l != toLine) piece else piece.trimEnd())
            if (l != toLine && !r.wrapped) append('\n')
        }
    }

    companion object {
        /**
         * Ячейки-ссылки строки [line] среди [count] строк [row]: OSC 8 и
         * адреса в тексте, в том числе перенесённые с соседних строк. Тот же
         * разбор — у снимка кадра экрана без замка сессии (терминал:A-10).
         */
        fun linkCells(count: Int, row: (Int) -> TerminalRow, line: Int): BooleanArray {
            if (line !in 0 until count) return BooleanArray(0)
            val r = row(line)
            val out = BooleanArray(r.cols) { r.linkAt(it) != null }
            var first = line
            while (first > 0 && row(first - 1).wrapped) first--
            var last = line
            while (last < count - 1 && row(last).wrapped) last++
            val text = StringBuilder()
            // Начало текста каждой ячейки строки [line] в логической строке.
            val starts = IntArray(r.cols) { -1 }
            for (l in first..last) {
                val cur = row(l)
                for (c in 0 until cur.cols) {
                    if (l == line) starts[c] = text.length
                    text.append(cur.text(c))
                }
            }
            for (m in LINK.findAll(text)) {
                val end = m.range.first + m.value.trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '»', '"', '\'').length
                for (c in 0 until r.cols) if (starts[c] in m.range.first until end) out[c] = true
            }
            // Правая половина широкого знака — как левая.
            for (c in 1 until r.cols) if (r.codePoint(c) == TerminalRow.WIDE_TAIL && out[c - 1]) out[c] = true
            return out
        }

        private val LINK = Regex("https?://[^\\s<>\"'`]+")

        /** Служебный OSC 9: число и `;` или конец (`9;4;1;50`, `9;9;C:\\`). */
        private val OSC9_SERVICE = Regex("^\\d+(;|$)")
        const val MAX_COLS = 1_000
        const val MAX_ROWS = 500
        private const val ESC = 0x1b

        /** Адрес ссылки OSC 8: только http(s), не длиннее [MAX_LINK]. */
        private val LINK_SCHEME = Regex("(?i)https?://\\S+")
        private const val MAX_LINK = 2_048

        /** Соединитель эмодзи (ZERO WIDTH JOINER). */
        private const val ZWJ = 0x200D
        private const val BEL = 0x07
        private const val ST_C1 = 0x9c
        private const val ESC_S = "\u001b"
        private const val MAX_PARAMS = 32
        private const val MAX_INTER = 2
        private const val MAX_PARAM = 65_535
        private const val MAX_OSC = 1 shl 20
        private const val MAX_TITLE = 1_000
    }
}
