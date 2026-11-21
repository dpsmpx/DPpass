package com.dpsmpx.dppass.app.alpine.terminal

/**
 * Строка экрана (D-71): символ ячейки — кодовая точка ([EMPTY] — пусто,
 * [WIDE_TAIL] — правая половина широкого символа), стиль — [Style].
 * Составные знаки (ударения, модификаторы эмодзи) — к ячейке основы, в
 * редкой карте. [wrapped] — строка продолжается следующей (мягкий
 * перенос): по нему строки собираются заново при смене ширины.
 */
class TerminalRow(cols: Int) {
    var chars: IntArray = IntArray(cols)
        private set
    var styles: LongArray = LongArray(cols)
        private set
    private var combining: HashMap<Int, String>? = null

    /** Ссылки OSC 8 у ячеек (терминал:A-19) — редкой картой, как составные знаки; только `http(s)`. */
    private var links: HashMap<Int, String>? = null
    var wrapped: Boolean = false

    val cols: Int get() = chars.size

    fun codePoint(col: Int): Int = chars[col]

    fun style(col: Int): Style = Style(styles[col])

    /** Текст ячейки с составными знаками; пустая — пробел, правая половина широкого — "". */
    fun text(col: Int): String = when (val cp = chars[col]) {
        EMPTY -> " "
        WIDE_TAIL -> ""
        else -> String(Character.toChars(cp)) + (combining?.get(col) ?: "")
    }

    fun set(col: Int, cp: Int, style: Style) {
        chars[col] = cp
        styles[col] = style.bits
        combining?.remove(col)
        links?.remove(col)
    }

    /** Ссылка OSC 8 ячейки; `null` — снять. */
    fun setLink(col: Int, url: String?) {
        if (url == null) {
            links?.remove(col)
        } else {
            (links ?: HashMap<Int, String>().also { links = it })[col] = url
        }
    }

    fun linkAt(col: Int): String? = links?.get(col)

    /**
     * Составной знак к ячейке. Сверх [MAX_COMBINING] знаков (в char) —
     * отбрасываются: поток из одних составных знаков иначе растил бы строку
     * ячейки без предела и копировал её на каждом знаке (ревью 17 октября 2026).
     */
    fun combine(col: Int, cp: Int) {
        val map = combining ?: HashMap<Int, String>().also { combining = it }
        val old = map[col] ?: ""
        if (old.length + Character.charCount(cp) > MAX_COMBINING) return
        map[col] = old + String(Character.toChars(cp))
    }

    fun combiningAt(col: Int): String? = combining?.get(col)

    /** Очистить [from] until [to] стилем [style] (фон стирания — текущий, как в xterm). */
    fun clear(from: Int, to: Int, style: Style) {
        val a = from.coerceIn(0, cols)
        val b = to.coerceIn(a, cols)
        chars.fill(EMPTY, a, b)
        styles.fill(style.bits, a, b)
        combining?.keys?.removeIf { it in a until b }
        links?.keys?.removeIf { it in a until b }
    }

    /** Вставить [n] пустых ячеек в [col]: хвост уходит вправо, лишнее отбрасывается. */
    fun insert(col: Int, n: Int, style: Style) {
        if (col >= cols) return
        val k = n.coerceAtMost(cols - col)
        System.arraycopy(chars, col, chars, col + k, cols - col - k)
        System.arraycopy(styles, col, styles, col + k, cols - col - k)
        shiftCombining(col, k)
        clear(col, col + k, style)
    }

    /** Удалить [n] ячеек в [col]: хвост сдвигается влево, справа — пусто. */
    fun delete(col: Int, n: Int, style: Style) {
        if (col >= cols) return
        val k = n.coerceAtMost(cols - col)
        System.arraycopy(chars, col + k, chars, col, cols - col - k)
        System.arraycopy(styles, col + k, styles, col, cols - col - k)
        // Знаки удалённых ячеек уходят вместе с ними, а не к соседу слева.
        combining?.keys?.removeIf { it in col until col + k }
        links?.keys?.removeIf { it in col until col + k }
        shiftCombining(col, -k)
        clear(cols - k, cols, style)
    }

    private fun shiftCombining(from: Int, by: Int) {
        for (map in listOfNotNull(combining, links)) {
            val moved = map.filterKeys { it >= from }.mapKeys { it.key + by }.filterKeys { it in 0 until cols }
            map.keys.removeIf { it >= from }
            map.putAll(moved)
        }
    }

    /** Новая ширина без переноса: обрезать или дополнить пустым. */
    fun resize(newCols: Int, style: Style = Style.DEFAULT) {
        if (newCols == cols) return
        val old = cols
        chars = chars.copyOf(newCols)
        styles = styles.copyOf(newCols)
        if (newCols > old) styles.fill(style.bits, old, newCols)
        combining?.keys?.removeIf { it >= newCols }
        links?.keys?.removeIf { it >= newCols }
        // Широкий символ, разрезанный краем, — пусто, а не половина.
        if (newCols > 0 && newCols < old && chars[newCols - 1] != EMPTY && CharWidth.of(chars[newCols - 1]) == 2) chars[newCols - 1] = EMPTY
    }

    /**
     * Копия в [dst] без новых массивов, если ширина та же: снимок кадра
     * экрана под замком сессии — каждый кадр (терминал:A-10).
     */
    fun copyInto(dst: TerminalRow) {
        if (dst.chars.size != cols) {
            dst.chars = IntArray(cols)
            dst.styles = LongArray(cols)
        }
        System.arraycopy(chars, 0, dst.chars, 0, cols)
        System.arraycopy(styles, 0, dst.styles, 0, cols)
        dst.combining = combining?.takeIf { it.isNotEmpty() }?.let { HashMap(it) }
        dst.links = links?.takeIf { it.isNotEmpty() }?.let { HashMap(it) }
        dst.wrapped = wrapped
    }

    fun copy(): TerminalRow = TerminalRow(0).also { r ->
        r.chars = chars.copyOf()
        r.styles = styles.copyOf()
        r.combining = combining?.let { HashMap(it) }
        r.links = links?.let { HashMap(it) }
        r.wrapped = wrapped
    }

    /** Текст строки без пустого хвоста. */
    fun text(): String {
        var last = cols - 1
        while (last >= 0 && chars[last] == EMPTY) last--
        return buildString { for (c in 0..last) append(text(c)) }
    }

    /** Сколько ячеек занято (до последней непустой включительно). */
    fun used(): Int {
        var last = cols - 1
        while (last >= 0 && chars[last] == EMPTY) last--
        return last + 1
    }

    companion object {
        const val EMPTY = 0
        const val WIDE_TAIL = -1

        /** Предел составных знаков ячейки, в char (VTE и xterm тоже держат немного). */
        const val MAX_COMBINING = 16
    }
}
