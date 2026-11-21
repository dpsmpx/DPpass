package com.dpsmpx.dppass.app.alpine.terminal

/** Клавиши без текста: стрелки, правка, функциональные (D-71). */
enum class Key {
    UP, DOWN, LEFT, RIGHT, HOME, END, PAGE_UP, PAGE_DOWN, INSERT, DELETE,
    ENTER, BACKSPACE, TAB, ESCAPE,
    F1, F2, F3, F4, F5, F6, F7, F8, F9, F10, F11, F12,
}

/** Модификаторы — битами, как в параметре xterm (`1 + сумма`). */
object Mod {
    const val SHIFT = 1
    const val ALT = 2
    const val CTRL = 4
}

/** Кнопка мыши в отчёте программе. */
enum class MouseButton(val code: Int) { LEFT(0), MIDDLE(1), RIGHT(2), NONE(3), WHEEL_UP(64), WHEEL_DOWN(65) }

/**
 * Ввод человека → байты для программы (D-71): последовательности xterm с
 * учётом режимов эмулятора (курсор приложения, перевод строки, вставка в
 * скобках, мышь, фокус). Чистые функции от состояния [TerminalEmulator] —
 * вызывающий держит тот же замок, что и при выводе.
 */
object KeyEncoder {
    private const val ESC = "\u001b"
    private const val JCUKEN = "йцукенгшщзхъфывапролджэячсмитьбюё"
    private const val QWERTY = "qwertyuiop[]asdfghjkl;'zxcvbnm,.`"

    fun key(key: Key, mods: Int, term: TerminalEmulator): ByteArray {
        val m = if (mods == 0) "" else "1;${1 + mods}"
        val s = when (key) {
            Key.UP -> cursor('A', m, term)
            Key.DOWN -> cursor('B', m, term)
            Key.RIGHT -> cursor('C', m, term)
            Key.LEFT -> cursor('D', m, term)
            Key.HOME -> cursor('H', m, term)
            Key.END -> cursor('F', m, term)
            Key.INSERT -> tilde(2, mods)
            Key.DELETE -> tilde(3, mods)
            Key.PAGE_UP -> tilde(5, mods)
            Key.PAGE_DOWN -> tilde(6, mods)
            Key.F1 -> ss3('P', m)
            Key.F2 -> ss3('Q', m)
            Key.F3 -> ss3('R', m)
            Key.F4 -> ss3('S', m)
            Key.F5 -> tilde(15, mods)
            Key.F6 -> tilde(17, mods)
            Key.F7 -> tilde(18, mods)
            Key.F8 -> tilde(19, mods)
            Key.F9 -> tilde(20, mods)
            Key.F10 -> tilde(21, mods)
            Key.F11 -> tilde(23, mods)
            Key.F12 -> tilde(24, mods)
            Key.ENTER -> alt(mods, if (term.newLineMode) "\r\n" else "\r")
            Key.BACKSPACE -> alt(mods, if (mods and Mod.CTRL != 0) "\b" else "\u007f")
            Key.TAB -> if (mods and Mod.SHIFT != 0) "$ESC[Z" else alt(mods, "\t")
            Key.ESCAPE -> alt(mods, ESC)
        }
        return s.toByteArray(Charsets.UTF_8)
    }

    /** Стрелки, Home и End: без модификаторов в режиме DECCKM — `ESC O x`. */
    private fun cursor(final: Char, m: String, term: TerminalEmulator): String = when {
        m.isNotEmpty() -> "$ESC[$m$final"
        term.cursorKeysApp -> "${ESC}O$final"
        else -> "$ESC[$final"
    }

    private fun tilde(n: Int, mods: Int): String = if (mods == 0) "$ESC[$n~" else "$ESC[$n;${1 + mods}~"

    private fun ss3(final: Char, m: String): String = if (m.isEmpty()) "${ESC}O$final" else "$ESC[$m$final"

    private fun alt(mods: Int, s: String): String = if (mods and Mod.ALT != 0) ESC + s else s

    /**
     * Символ с модификаторами: Ctrl — управляющий код (`Ctrl+C` → 0x03,
     * `Ctrl+[` → ESC, `Ctrl+?` → DEL), Alt — приставка ESC. Shift уже учтён
     * клавиатурой в самом символе.
     */
    fun char(cp: Int, mods: Int): ByteArray {
        val c = if (mods and Mod.CTRL != 0) control(cp) else cp
        val s = String(Character.toChars(c))
        return alt(mods, s).toByteArray(Charsets.UTF_8)
    }

    /**
     * Ctrl с русской раскладкой — по месту клавиши (ЙЦУКЕН → QWERTY): Ctrl+С
     * прерывает, как Ctrl+C (ревью 17 октября 2026). Без этого шла бы сама
     * буква, и Ctrl+C, Ctrl+D, Ctrl+R не работали бы без смены раскладки.
     */
    private fun latinKey(cp: Int): Int {
        if (cp !in 0x400..0x4ff) return cp
        val i = JCUKEN.indexOf(Character.toLowerCase(cp).toChar())
        return if (i >= 0) QWERTY[i].code else cp
    }

    private fun control(cp: Int): Int = when (val c = latinKey(cp)) {
        in 'a'.code..'z'.code -> c - 'a'.code + 1
        in 'A'.code..'Z'.code -> c - 'A'.code + 1
        ' '.code, '@'.code, '2'.code -> 0
        '['.code, '3'.code -> 0x1b
        '\\'.code, '4'.code -> 0x1c
        ']'.code, '5'.code -> 0x1d
        '^'.code, '~'.code, '6'.code -> 0x1e
        '_'.code, '/'.code, '7'.code -> 0x1f
        '?'.code, '8'.code -> 0x7f
        else -> cp
    }

    /**
     * Вставка из буфера обмена. Управляющие символы, кроме табуляции,
     * выбрасываются (T-вставка: ESC в тексте закрыл бы скобки 2004 и
     * выполнил остаток как ввод), перевод строки — CR, как от Enter.
     */
    fun paste(text: String, term: TerminalEmulator): ByteArray {
        val clean = buildString {
            val norm = text.replace("\r\n", "\r").replace('\n', '\r')
            norm.codePoints().forEach { cp ->
                if (cp == '\t'.code || cp == '\r'.code || (cp >= 0x20 && cp != 0x7f && cp !in 0x80..0x9f)) appendCodePoint(cp)
            }
        }
        val s = if (term.bracketedPaste) "$ESC[200~$clean$ESC[201~" else clean
        return s.toByteArray(Charsets.UTF_8)
    }

    /**
     * Событие мыши для программы, если она его просит ([TerminalEmulator.mouseMode]):
     * [col] и [row] — ячейка с 0; [pressed] — нажатие (иначе отпускание);
     * [motion] — движение. `null` — программа это событие не отслеживает
     * или координата не выражается в старой записи (больше 223).
     */
    fun mouse(button: MouseButton, col: Int, row: Int, pressed: Boolean, motion: Boolean, mods: Int, term: TerminalEmulator): ByteArray? {
        val wanted = when (term.mouseMode) {
            MouseMode.NONE -> false
            MouseMode.PRESS -> !motion
            MouseMode.DRAG -> !motion || button != MouseButton.NONE
            MouseMode.ANY -> true
        }
        if (!wanted) return null
        val wheel = button == MouseButton.WHEEL_UP || button == MouseButton.WHEEL_DOWN
        if (wheel && !pressed) return null
        var b = button.code
        if (motion) b += 32
        if (mods and Mod.SHIFT != 0) b += 4
        if (mods and Mod.ALT != 0) b += 8
        if (mods and Mod.CTRL != 0) b += 16
        if (term.mouseSgr) return "$ESC[<$b;${col + 1};${row + 1}${if (pressed || motion) 'M' else 'm'}".toByteArray(Charsets.UTF_8)
        // Старая запись: отпускание — кнопка 3, байты — со смещением 32.
        if (!pressed && !motion) b = (b and 3.inv()) or 3
        if (col + 1 + 32 > 255 || row + 1 + 32 > 255) return null
        return byteArrayOf(0x1b, '['.code.toByte(), 'M'.code.toByte(), (32 + b).toByte(), (32 + col + 1).toByte(), (32 + row + 1).toByte())
    }

    /** Фокус окна (DECSET 1004): `ESC [ I` и `ESC [ O`; не просили — `null`. */
    fun focus(gained: Boolean, term: TerminalEmulator): ByteArray? =
        if (term.focusEvents) (if (gained) "$ESC[I" else "$ESC[O").toByteArray(Charsets.UTF_8) else null
}
