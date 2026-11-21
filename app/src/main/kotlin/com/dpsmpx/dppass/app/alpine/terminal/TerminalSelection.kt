package com.dpsmpx.dppass.app.alpine.terminal

/**
 * Выделение текста терминала (аудит UI/UX 5 ноября 2026, терминал:A-2):
 * долгое нажатие выделяет слово, как принято в Android; ссылка в
 * выделенном — для «Открыть» и «Копировать ссылку» меню (терминал:A-19).
 */
object TerminalSelection {
    /** Знаки внутри слова, кроме букв и цифр: пути, адреса, ключи — одним словом. */
    private const val WORD_EXTRA = "-_./:~@%+=?&#\$"

    private val LINK = Regex("""^https?://\S+$""")

    fun isWordChar(cp: Int): Boolean = Character.isLetterOrDigit(cp) || (cp in 0..0xFFFF && cp.toChar() in WORD_EXTRA)

    /**
     * Столбцы слова вокруг [col] в строке [row]; правая половина широкого
     * знака — часть знака. Под пальцем не слово (пробел, скобка) — один
     * этот столбец.
     */
    fun word(row: TerminalRow, col: Int): IntRange {
        if (row.cols == 0) return 0..0
        var c = col.coerceIn(0, row.cols - 1)
        if (row.codePoint(c) == TerminalRow.WIDE_TAIL && c > 0) c--
        fun word(x: Int): Boolean {
            val cp = row.codePoint(x)
            return if (cp == TerminalRow.WIDE_TAIL) x > 0 && isWordChar(row.codePoint(x - 1)) else isWordChar(cp)
        }
        if (!word(c)) return c..(if (c + 1 < row.cols && row.codePoint(c + 1) == TerminalRow.WIDE_TAIL) c + 1 else c)
        var start = c
        while (start > 0 && word(start - 1)) start--
        var end = c
        while (end + 1 < row.cols && word(end + 1)) end++
        return start..end
    }

    /** Ссылка `http(s)` — если выделено ровно одно: без пробелов, хвостовая пунктуация отрезана. */
    fun link(text: String): String? {
        val t = text.trim().replace("\n", "").trimEnd('.', ',', ';', ':', '!', '?', ')', ']', '»', '"', '\'')
        return t.takeIf { LINK.matches(it) }
    }
}
