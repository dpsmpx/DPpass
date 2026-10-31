package com.dpsmpx.dppass.desktop.ui

import com.dpsmpx.dppass.connection.AnalyzerView
import com.dpsmpx.dppass.connection.CellLabels
import com.dpsmpx.dppass.connection.ConnColumn
import com.dpsmpx.dppass.connection.ConnSort
import com.dpsmpx.dppass.connection.ConnectionAnalyzer
import com.dpsmpx.dppass.connection.ConnectionCells
import com.dpsmpx.dppass.connection.ConnectionOwners
import com.dpsmpx.dppass.connection.ConnectionRow
import com.dpsmpx.dppass.connection.ConnectionTable
import com.dpsmpx.dppass.connection.Tone
import com.dpsmpx.dppass.connection.UniqueColumn
import com.dpsmpx.dppass.connection.UniqueEntry
import com.dpsmpx.dppass.connection.UniqueSort
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.awt.BorderLayout
import java.awt.Color
import java.awt.Component
import java.awt.FlowLayout
import java.awt.event.HierarchyEvent
import java.awt.event.MouseAdapter
import java.awt.event.MouseEvent
import java.util.Locale
import javax.swing.BoxLayout
import javax.swing.ButtonGroup
import javax.swing.JCheckBox
import javax.swing.JLabel
import javax.swing.JOptionPane
import javax.swing.JPanel
import javax.swing.JScrollPane
import javax.swing.JTable
import javax.swing.JTextField
import javax.swing.JToggleButton
import javax.swing.SwingConstants
import javax.swing.event.DocumentEvent
import javax.swing.event.DocumentListener
import javax.swing.table.AbstractTableModel
import javax.swing.table.DefaultTableCellRenderer

/**
 * «Соединения» на ПК (D-106): таблица соединений через DPpass — открытых и
 * закрытых за 5 минут — как в диспетчере задач и `top`: столбцы, цвет
 * состояний и значений, сортировка нажатием на заголовок, поиск. «Журнал» —
 * уникальные соединения на диске, «Сохранять уникальные соединения» и
 * «Очистить журнал подключений». Порядок, поиск, цвета и текст ячеек —
 * общие с телефоном (`ConnectionTable`, `ConnectionCells`). Обновление — раз
 * в секунду, пока вкладка видна.
 */
class ConnectionsPanel(
    private val analyzer: ConnectionAnalyzer,
    private val owners: ConnectionOwners,
    private val scope: CoroutineScope,
) : JPanel(BorderLayout()) {
    private var journal = false
    private var query = ""
    var sort: ConnSort = ConnectionTable.DEFAULT_SORT
        private set
    var uniqueSort: UniqueSort = UniqueSort(UniqueColumn.LAST, descending = true)
        private set
    private var view: AnalyzerView? = null
    private var ticker: Job? = null

    /** Строки в порядке таблицы. */
    var shown: List<ConnectionRow> = emptyList()
        private set
    var shownUnique: List<UniqueEntry> = emptyList()
        private set

    private val enabled = JCheckBox("Анализатор соединений").apply {
        toolTipText = "Показывает соединения через DPpass. Выключен — нет ни учёта, ни нагрузки."
        addActionListener { change { analyzer.setEnabled(isSelected) } }
    }
    private val keep = JCheckBox("Сохранять уникальные соединения").apply {
        toolTipText = "По строке на каждое соединение: приложение, адрес, порт, число подключений и когда было последнее. На диске, зашифровано."
        addActionListener { change { analyzer.setKeepUnique(isSelected) } }
    }
    private val clear = Widgets.button("Очистить журнал подключений…") { confirmClear() }
    private val liveTab = JToggleButton("Соединения", true).apply { addActionListener { switchTo(journal = false) } }
    internal val journalTab = JToggleButton("Журнал").apply { addActionListener { switchTo(journal = true) } }
    internal val search = JTextField(SEARCH_COLUMNS).apply {
        toolTipText = "Слова через пробел: адрес, приложение, маршрут, состояние"
        document.addDocumentListener(
            object : DocumentListener {
                override fun insertUpdate(e: DocumentEvent) = typed()
                override fun removeUpdate(e: DocumentEvent) = typed()
                override fun changedUpdate(e: DocumentEvent) = typed()
            },
        )
    }
    val status: JLabel = Widgets.caption()

    private val model = Model()
    val table: JTable = JTable(model).apply {
        autoResizeMode = JTable.AUTO_RESIZE_OFF
        fillsViewportHeight = true
        rowHeight = rowHeight + ROW_EXTRA
        setShowGrid(true)
        gridColor = Theme.palette.outline
        setDefaultRenderer(Any::class.java, Renderer())
        tableHeader.reorderingAllowed = false
        tableHeader.addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    val col = columnAtPoint(e.point)
                    if (col >= 0) headerClicked(convertColumnIndexToModel(col))
                }
            },
        )
        addMouseListener(
            object : MouseAdapter() {
                override fun mouseClicked(e: MouseEvent) {
                    if (e.clickCount == 2) rowAtPoint(e.point).takeIf { it >= 0 }?.let(::details)
                }
            },
        )
    }

    private val labels = CellLabels(
        open = "Открыто", closed = "Закрыто", failed = "Прервано",
        routeProxy = "Сервер", routeDirect = "Напрямую", routeBlock = "Блок", routeDns = "DNS",
        inTun = "VPN", inLocal = "Без VPN", inShare = "Раздача", inSelf = "DPpass",
        noAnswer = "нет ответа", ms = "мс", s = "с", percent = "%d %%", locale = Locale.forLanguageTag("ru"),
        bytes = Format::bytes, speed = { Format.bytes(it) + "/с" },
    )

    init {
        background = Theme.palette.bg
        border = Widgets.pad(4)
        val top = JPanel().apply {
            layout = BoxLayout(this, BoxLayout.Y_AXIS)
            isOpaque = false
            add(Widgets.title("Соединения").also { it.border = Widgets.pad(1) })
            add(
                row(enabled, keep, clear).also {
                    ButtonGroup().apply {
                        add(liveTab)
                        add(journalTab)
                    }
                },
            )
            add(row(liveTab, journalTab, JLabel("Поиск:"), search))
            add(row(status))
        }
        add(top, BorderLayout.NORTH)
        add(JScrollPane(table), BorderLayout.CENTER)
        add(
            Widgets.still(Widgets.note()).apply {
                text = "Видны соединения через DPpass: приложения мимо туннеля здесь не видны. Порции — буферы данных, которые ядро " +
                    "передаёт за раз, а не IP-пакеты. Нажатие на заголовок — сортировка, двойной щелчок по строке — подробности."
            },
            BorderLayout.SOUTH,
        )
        addHierarchyListener { e ->
            if (e.changeFlags and HierarchyEvent.SHOWING_CHANGED.toLong() != 0L) if (isShowing) start() else stop()
        }
        render()
    }

    private fun row(vararg parts: Component): JPanel = JPanel(FlowLayout(FlowLayout.LEFT, Widgets.STEP * 2, Widgets.STEP)).apply {
        isOpaque = false
        alignmentX = LEFT_ALIGNMENT
        parts.forEach { add(it) }
    }

    /** Опрос раз в секунду, пока вкладка видна. */
    fun start() {
        ticker?.cancel()
        ticker = scope.launch(Edt) {
            while (isActive) {
                refresh()
                delay(TICK_MILLIS)
            }
        }
    }

    fun stop() {
        ticker?.cancel()
        ticker = null
    }

    /** Один опрос анализатора (в фоне) и перерисовка. */
    suspend fun refresh() {
        view = withContext(Dispatchers.IO) { analyzer.poll(owners) }
        render()
    }

    private fun typed() {
        query = search.text
        render()
    }

    private fun switchTo(journal: Boolean) {
        this.journal = journal
        render()
    }

    fun headerClicked(col: Int) {
        if (journal) uniqueSort = uniqueSort.toggled(UNIQUE[col]) else sort = sort.toggled(LIVE[col])
        render()
    }

    fun render() {
        val s = analyzer.settings()
        enabled.isSelected = s.enabled
        keep.isSelected = s.keepUnique
        liveTab.isSelected = !journal
        journalTab.isSelected = journal
        keep.isVisible = journal
        clear.isVisible = journal
        status.foreground = Theme.palette.textSecondary
        val selected = table.selectedRow.takeIf { it >= 0 }
        val keepId = selected?.let { if (journal) null else shown.getOrNull(it)?.id }
        if (journal) {
            val all = analyzer.unique()
            shownUnique = ConnectionTable.unique(all, query, uniqueSort)
            val full = view?.journalFull == true
            if (full) status.foreground = Theme.palette.warning
            status.text = when {
                full -> "Журнал полон (строк: ${all.size}): новые соединения не записываются. Очистите журнал."
                all.isEmpty() -> "Журнал пуст."
                query.isNotBlank() -> "Показано ${shownUnique.size} из ${all.size}"
                else -> "Строк в журнале: ${all.size}"
            }
        } else {
            val v = view
            shown = if (s.enabled && v != null) ConnectionTable.view(v.rows, query, sort) { ConnectionCells.searchLabels(it, labels) } else emptyList()
            status.text = when {
                !s.enabled -> "Включите анализатор — здесь появятся соединения: открытые и закрытые за последние 5 минут."
                v == null -> ""
                !v.available -> "Ядро не загружено — соединения не учитываются."
                v.rows.isEmpty() -> "Соединений нет: за последние 5 минут через DPpass ничего не шло."
                else -> buildString {
                    append("Открыто ${v.open} · прервано ${v.failed} · ↓ ${labels.speed(v.downRate)} · ↑ ${labels.speed(v.upRate)}")
                    if (query.isNotBlank()) append(" · показано ${shown.size} из ${v.rows.size}")
                    if (v.skipped > 0) append(" · не учтено ядром: ${v.skipped}")
                    if (v.malformed > 0) append(" · строк не по договору моста: ${v.malformed}")
                }
            }
            if (v != null && (v.skipped > 0 || v.malformed > 0)) status.foreground = Theme.palette.warning
        }
        model.update()
        // Выбранная строка остаётся выбранной, хотя порядок сменился.
        keepId?.let { id -> shown.indexOfFirst { it.id == id }.takeIf { it >= 0 }?.let { table.setRowSelectionInterval(it, it) } }
    }

    private fun details(index: Int) {
        if (journal) return
        val row = shown.getOrNull(index) ?: return
        val c = row.connection
        val text = buildString {
            appendLine("Адрес: ${row.host}")
            if (c.domain.isNotEmpty() && c.domain != row.host) appendLine("Имя сайта: ${c.domain}")
            appendLine("Назначение: ${c.target}")
            if (c.source.isNotEmpty()) appendLine("Источник: ${c.source}")
            appendLine("Начало: ${Format.date(row.startedAtMillis)}")
            for (col in LIVE) if (col != ConnColumn.HOST) appendLine("${title(col)}: ${ConnectionCells.text(row, col, labels)}")
            append("Теги ядра: ${listOf(c.inbound, c.route).filter { it.isNotEmpty() }.joinToString(" → ")}")
        }
        JOptionPane.showMessageDialog(this, Widgets.still(Widgets.note()).apply { this.text = text }, row.host, JOptionPane.PLAIN_MESSAGE)
    }

    private fun confirmClear() {
        val n = analyzer.unique().size
        val question = "Стереть журнал уникальных соединений? Строк: $n."
        val answer = JOptionPane.showConfirmDialog(this, question, "Очистить журнал подключений", JOptionPane.OK_CANCEL_OPTION)
        if (answer == JOptionPane.OK_OPTION) change { analyzer.clearJournal() }
    }

    private fun change(action: () -> Outcome<*>) {
        val r = action()
        if (r is Outcome.Failure) JOptionPane.showMessageDialog(this, Widgets.describe(r.errors.first()), "Соединения", JOptionPane.WARNING_MESSAGE)
        render()
    }

    /** Цвет текста по смыслу; [row] — тон строки (закрытые приглушены). */
    fun foreground(t: Tone, row: Tone): Color = with(Theme.palette) {
        when (t) {
            Tone.NORMAL -> if (row == Tone.MUTED) textSecondary else text
            Tone.MUTED -> textSecondary
            Tone.GOOD -> success
            Tone.INFO -> primary
            Tone.WARN -> warning
            Tone.BAD -> error
            Tone.HEAT_LOW, Tone.HEAT_MID, Tone.HEAT_HIGH -> text
        }
    }

    /** Подсветка величины — фоном, как в диспетчере задач; null — фон обычный. */
    fun heat(t: Tone): Color? {
        val alpha = when (t) {
            Tone.HEAT_LOW -> HEAT_LOW
            Tone.HEAT_MID -> HEAT_MID
            Tone.HEAT_HIGH -> return Theme.palette.primaryContainer
            else -> return null
        }
        val (bg, c) = Theme.palette.surface to Theme.palette.primaryContainer
        fun mix(a: Int, b: Int) = (a + (b - a) * alpha / 255f).toInt()
        return Color(mix(bg.red, c.red), mix(bg.green, c.green), mix(bg.blue, c.blue))
    }

    private inner class Model : AbstractTableModel() {
        private var columns = -1

        fun update() {
            val n = if (journal) UNIQUE.size else LIVE.size
            if (n != columns || journal != lastJournal) {
                columns = n
                lastJournal = journal
                fireTableStructureChanged()
                widths()
            } else {
                fireTableDataChanged()
            }
            table.tableHeader.repaint()
        }

        private var lastJournal = false

        override fun getRowCount(): Int = if (journal) shownUnique.size else shown.size

        override fun getColumnCount(): Int = if (journal) UNIQUE.size else LIVE.size

        override fun getColumnName(column: Int): String {
            val (title, sorted, down) = if (journal) {
                Triple(title(UNIQUE[column]), uniqueSort.column == UNIQUE[column], uniqueSort.descending)
            } else {
                Triple(title(LIVE[column]), sort.column == LIVE[column], sort.descending)
            }
            return if (sorted) "$title ${if (down) "▼" else "▲"}" else title
        }

        override fun getValueAt(rowIndex: Int, columnIndex: Int): Any = if (journal) {
            ConnectionCells.unique(shownUnique[rowIndex], UNIQUE[columnIndex], labels, Format::date)
        } else {
            ConnectionCells.text(shown[rowIndex], LIVE[columnIndex], labels)
        }

        /** Ширина — по образцу значения и заголовку: числа не прыгают при обновлении. */
        private fun widths() {
            val fm = table.getFontMetrics(table.font)
            for (i in 0 until columnCount) {
                val sample = if (journal) ConnectionCells.sample(UNIQUE[i], labels, Format::date) else ConnectionCells.sample(LIVE[i], labels)
                val w = maxOf(fm.stringWidth(sample), fm.stringWidth(getColumnName(i) + " ▼")) + CELL_PAD
                table.columnModel.getColumn(i).preferredWidth = w
            }
        }
    }

    private inner class Renderer : DefaultTableCellRenderer() {
        override fun getTableCellRendererComponent(table: JTable, value: Any?, isSelected: Boolean, hasFocus: Boolean, row: Int, column: Int): Component {
            super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column)
            val numeric = if (journal) UNIQUE[column].numeric else LIVE[column].numeric
            horizontalAlignment = if (numeric) SwingConstants.RIGHT else SwingConstants.LEFT
            if (isSelected) return this
            if (journal) {
                foreground = if (UNIQUE[column] == UniqueColumn.APP && shownUnique[row].key.app == null) Theme.palette.textSecondary else Theme.palette.text
                background = Theme.palette.surface
            } else {
                val r = shown[row]
                val tone = ConnectionTable.tone(r, LIVE[column])
                foreground = foreground(tone, ConnectionTable.rowTone(r))
                background = heat(tone) ?: Theme.palette.surface
            }
            return this
        }
    }

    companion object {
        private const val TICK_MILLIS = 1_000L
        private const val SEARCH_COLUMNS = 24
        private const val ROW_EXTRA = 6
        private const val CELL_PAD = 16
        private const val HEAT_LOW = 0x55
        private const val HEAT_MID = 0xAA

        /** Порядок столбцов на ПК: как в диспетчере задач — состояние и имя впереди, дальше нагрузка. */
        val LIVE: List<ConnColumn> = listOf(
            ConnColumn.STATE, ConnColumn.HOST, ConnColumn.APP, ConnColumn.DOWN_RATE, ConnColumn.UP_RATE, ConnColumn.DOWN_BYTES,
            ConnColumn.UP_BYTES, ConnColumn.DOWN_CHUNKS, ConnColumn.UP_CHUNKS, ConnColumn.FIRST_BYTE, ConnColumn.RELIABILITY,
            ConnColumn.RECENT, ConnColumn.DURATION, ConnColumn.IDLE, ConnColumn.ROUTE, ConnColumn.PROTOCOL, ConnColumn.NETWORK,
            ConnColumn.PORT, ConnColumn.INBOUND,
        )
        val UNIQUE: List<UniqueColumn> =
            listOf(UniqueColumn.HOST, UniqueColumn.APP, UniqueColumn.PORT, UniqueColumn.NETWORK, UniqueColumn.COUNT, UniqueColumn.LAST)

        fun title(c: ConnColumn): String = when (c) {
            ConnColumn.STATE -> "Состояние"
            ConnColumn.APP -> "Процесс"
            ConnColumn.HOST -> "Адрес"
            ConnColumn.PORT -> "Порт"
            ConnColumn.NETWORK -> "Сеть"
            ConnColumn.PROTOCOL -> "Протокол"
            ConnColumn.ROUTE -> "Маршрут"
            ConnColumn.INBOUND -> "Вход"
            ConnColumn.DURATION -> "Длится"
            ConnColumn.IDLE -> "Простой"
            ConnColumn.FIRST_BYTE -> "Ответ"
            ConnColumn.UP_RATE -> "↑ /с"
            ConnColumn.DOWN_RATE -> "↓ /с"
            ConnColumn.UP_BYTES -> "Отправлено"
            ConnColumn.DOWN_BYTES -> "Получено"
            ConnColumn.UP_CHUNKS -> "Порций ↑"
            ConnColumn.DOWN_CHUNKS -> "Порций ↓"
            ConnColumn.RECENT -> "За 5 мин"
            ConnColumn.RELIABILITY -> "Надёжность"
        }

        fun title(c: UniqueColumn): String = when (c) {
            UniqueColumn.APP -> "Процесс"
            UniqueColumn.HOST -> "Адрес"
            UniqueColumn.PORT -> "Порт"
            UniqueColumn.NETWORK -> "Сеть"
            UniqueColumn.COUNT -> "Подключений"
            UniqueColumn.LAST -> "Последнее"
        }
    }
}
