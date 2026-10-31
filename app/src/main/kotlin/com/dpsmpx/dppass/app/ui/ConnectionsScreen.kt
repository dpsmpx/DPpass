package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.view.View
import android.widget.FrameLayout
import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.AppGraph
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.AnalyzerSettings
import com.dpsmpx.dppass.connection.AnalyzerView
import com.dpsmpx.dppass.connection.CellLabels
import com.dpsmpx.dppass.connection.ConnColumn
import com.dpsmpx.dppass.connection.ConnSort
import com.dpsmpx.dppass.connection.ConnectionCells
import com.dpsmpx.dppass.connection.ConnectionRow
import com.dpsmpx.dppass.connection.ConnectionTable
import com.dpsmpx.dppass.connection.Tone
import com.dpsmpx.dppass.connection.UniqueColumn
import com.dpsmpx.dppass.connection.UniqueEntry
import com.dpsmpx.dppass.connection.UniqueSort
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.ConnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Соединения» (D-106): таблица соединений через DPpass — открытых и
 * закрытых за 5 минут — как в диспетчере задач и `top`: столбцы, цвет
 * состояний и значений, сортировка нажатием на заголовок, поиск. Вкладка
 * «Журнал» — уникальные соединения на диске, «Сохранять уникальные
 * соединения» и «Очистить журнал подключений». Обновление — раз в
 * секунду, пока экран виден; выключенный анализатор ничего не учитывает.
 */
class ConnectionsScreen(host: Host) : SubScreen(host, R.string.conn_title) {
    override val scrolls: Boolean = false

    private var tab = TAB_LIVE
    private var query = ""
    private var sort: ConnSort = ConnectionTable.DEFAULT_SORT
    private var uniqueSort = UniqueSort(UniqueColumn.LAST, descending = true)
    private var last: AnalyzerView? = null

    /** Строки в порядке таблицы — для подробностей по нажатию. */
    private var shown: List<ConnectionRow> = emptyList()
    private var shownUnique: List<UniqueEntry> = emptyList()
    private var ticker: Job? = null

    private val labels: CellLabels by lazy {
        CellLabels(
            open = context.getString(R.string.conn_state_open),
            closed = context.getString(R.string.conn_state_closed),
            failed = context.getString(R.string.conn_state_failed),
            routeProxy = context.getString(R.string.conn_route_proxy),
            routeDirect = context.getString(R.string.conn_route_direct),
            routeBlock = context.getString(R.string.conn_route_block),
            routeDns = context.getString(R.string.conn_route_dns),
            inTun = context.getString(R.string.conn_in_tun),
            inLocal = context.getString(R.string.conn_in_local),
            inShare = context.getString(R.string.conn_in_share),
            inSelf = context.getString(R.string.conn_in_self),
            noAnswer = context.getString(R.string.conn_no_answer),
            ms = context.getString(R.string.conn_unit_ms),
            s = context.getString(R.string.conn_unit_s),
            percent = context.getString(R.string.conn_percent),
            locale = context.resources.configuration.locales[0],
            bytes = { bytes(it) },
            speed = { speed(it) },
        )
    }

    private val owners get() = AppGraph.graph(context).owners

    private fun app(owner: String): String = owners.label(owner)

    private val table = GridTable(context).apply {
        onHeader = { col -> headerTapped(col) }
        onRow = { row -> rowTapped(row) }
    }
    private val status = Ui.text(context, R.style.Text_DPpass_Caption)
    private val switches = Ui.listCard(context)
    private val tabs = FrameLayout(context)
    private val search = Ui.searchField(context, R.string.conn_search) {
        query = it
        draw()
    }

    private val liveColumns: List<GridTable.Column> by lazy {
        LIVE.map { GridTable.Column(context.getString(title(it)), ConnectionCells.sample(it, labels), it.numeric) }
    }
    private val uniqueColumns: List<GridTable.Column> by lazy {
        UNIQUE.map { GridTable.Column(context.getString(title(it)), ConnectionCells.sample(it, labels, ::dateTime), it.numeric) }
    }

    override fun content(): View = Ui.column(context).apply {
        val controls = Ui.column(context, 8).apply {
            val side = Ui.dp(context, 16)
            setPadding(side, Ui.dp(context, 8), side, Ui.dp(context, 8))
            addView(switches, Ui.matchWidth())
            addView(tabs, Ui.matchWidth())
            addView(search, Ui.matchWidth())
            addView(status, Ui.matchWidth())
        }
        addView(controls, Ui.matchWidth())
        addView(table, LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, 0, 1f))
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.conn_note)).apply {
                val side = Ui.dp(context, 16)
                setPadding(side, Ui.dp(context, 8), side, Ui.dp(context, 12))
            },
            Ui.matchWidth(),
        )
    }

    override fun render(status: TunnelStatus) = draw()

    override fun onShown() {
        ticker?.cancel()
        ticker = host.scope.launch {
            while (isActive) {
                val core = host.graph?.core
                if (core != null) {
                    val owners = owners
                    last = withContext(Dispatchers.Default) { core.analyzer.poll(owners) }
                    draw()
                }
                delay(TICK_MILLIS)
            }
        }
    }

    override fun onHidden() {
        ticker?.cancel()
        ticker = null
    }

    /** Что нарисовано в переключателях: без перемен — не пересоздаются (фокус TalkBack не прыгает раз в секунду). */
    private var drawn: Pair<AnalyzerSettings, Int>? = null

    private fun draw() {
        val core = host.graph?.core ?: return
        val settings = core.analyzer.settings()
        if (drawn != settings to tab) {
            drawn = settings to tab
            drawSwitches(settings)
            drawTabs()
        }
        if (tab == TAB_LIVE) drawLive(settings) else drawUnique()
    }

    private fun drawSwitches(s: AnalyzerSettings) {
        switches.removeAllViews()
        switches.addView(
            Ui.switchRow(context, R.drawable.ic_speed, context.getString(R.string.conn_switch), context.getString(R.string.conn_switch_note), s.enabled) {
                change { host.graph?.core?.analyzer?.setEnabled(it) }
            },
            Ui.matchWidth(),
        )
        if (tab != TAB_JOURNAL) return
        switches.addView(Ui.divider(context))
        switches.addView(
            Ui.switchRow(context, R.drawable.ic_log, context.getString(R.string.conn_keep), context.getString(R.string.conn_keep_note), s.keepUnique) {
                change { host.graph?.core?.analyzer?.setKeepUnique(it) }
            },
            Ui.matchWidth(),
        )
        switches.addView(Ui.divider(context))
        switches.addView(Ui.ListRow(context, R.drawable.ic_delete, context.getString(R.string.conn_clear)).onClick { confirmClear() }, Ui.matchWidth())
    }

    private fun drawTabs() {
        tabs.removeAllViews()
        val options = listOf(context.getString(R.string.conn_tab_live), context.getString(R.string.conn_tab_journal))
        tabs.addView(
            Ui.segmented(context, options, tab) {
                tab = it
                draw()
            },
            Ui.matchWidth(),
        )
    }

    private fun drawLive(s: AnalyzerSettings) {
        val v = last
        val text = when {
            !s.enabled -> context.getString(R.string.conn_off_hint)
            v == null -> ""
            !v.available -> context.getString(R.string.conn_unavailable)
            v.rows.isEmpty() -> context.getString(R.string.conn_empty)
            else -> null
        }
        shown = if (s.enabled && v != null) ConnectionTable.view(v.rows, query, sort) { ConnectionCells.searchLabels(it, labels, ::app) } else emptyList()
        status.setTextColor(context.getColor(R.color.text_secondary))
        status.text = if (text != null || v == null) {
            text.orEmpty()
        } else {
            buildString {
                append(context.getString(R.string.conn_summary, v.open, v.failed, speed(v.downRate), speed(v.upRate)))
                if (query.isNotBlank()) append('\n').append(context.getString(R.string.conn_shown, shown.size, v.rows.size))
                if (shown.isEmpty()) append('\n').append(context.getString(R.string.conn_nothing_found))
                if (v.skipped > 0) append('\n').append(context.getString(R.string.conn_skipped, v.skipped))
                if (v.malformed > 0) append('\n').append(context.getString(R.string.conn_malformed, v.malformed))
            }
        }
        if (v != null && (v.skipped > 0 || v.malformed > 0)) status.setTextColor(context.getColor(R.color.warning))
        table.visibility = if (shown.isEmpty()) View.INVISIBLE else View.VISIBLE
        table.model = LiveModel(shown)
    }

    private fun drawUnique() {
        val analyzer = host.graph?.core?.analyzer ?: return
        val all = analyzer.unique()
        shownUnique = ConnectionTable.unique(all, query, uniqueSort)
        val full = last?.journalFull == true
        status.setTextColor(context.getColor(if (full) R.color.warning else R.color.text_secondary))
        status.text = when {
            full -> context.getString(R.string.conn_journal_full, all.size)
            all.isEmpty() -> context.getString(R.string.conn_journal_empty)
            query.isNotBlank() -> context.getString(R.string.conn_shown, shownUnique.size, all.size)
            else -> context.getString(R.string.conn_journal_count, all.size)
        }
        table.visibility = if (shownUnique.isEmpty()) View.INVISIBLE else View.VISIBLE
        table.model = UniqueModel(shownUnique)
    }

    private fun headerTapped(col: Int) {
        if (tab == TAB_LIVE) sort = sort.toggled(LIVE[col]) else uniqueSort = uniqueSort.toggled(UNIQUE[col])
        draw()
    }

    private fun rowTapped(index: Int) {
        if (tab != TAB_LIVE) return
        val row = shown.getOrNull(index) ?: return
        val c = row.connection
        val items = buildList {
            add(R.string.conn_col_host to row.host)
            if (c.domain.isNotEmpty() && c.domain != row.host) add(R.string.conn_detail_domain to c.domain)
            add(R.string.conn_detail_target to c.target)
            if (c.source.isNotEmpty()) add(R.string.conn_detail_source to c.source)
            row.app?.let {
                add(R.string.conn_col_app to app(it))
                add(R.string.conn_detail_package to it)
            }
            add(R.string.conn_detail_started to dateTime(row.startedAtMillis))
            for (col in LIVE) if (col != ConnColumn.HOST && col != ConnColumn.APP) add(title(col) to ConnectionCells.text(row, col, labels, ::app))
            add(R.string.conn_detail_tag to listOf(c.inbound, c.route).filter { it.isNotEmpty() }.joinToString(" → "))
        }
        val list = Ui.listCard(context).apply {
            items.forEachIndexed { i, (label, value) ->
                if (i > 0) addView(Ui.divider(context, 16))
                addView(Ui.ListRow(context, null, context.getString(label)).subtitle(value), Ui.matchWidth())
            }
        }
        Ui.sheet(context, row.host, list).show()
    }

    private fun confirmClear() {
        val analyzer = host.graph?.core?.analyzer ?: return
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(context.getString(R.string.conn_clear_confirm, analyzer.unique().size))
                .setPositiveButton(android.R.string.ok) { _, _ -> change { analyzer.clearJournal() } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    private fun change(action: () -> Outcome<*>?) {
        val r = action() ?: return
        if (r is Outcome.Failure) host.problem(context.getString(R.string.conn_title), r.errors.first())
        draw()
    }

    private fun color(t: Tone, row: Tone): Int = context.getColor(
        when (t) {
            Tone.NORMAL -> if (row == Tone.MUTED) R.color.text_secondary else R.color.text
            Tone.MUTED -> R.color.text_secondary
            Tone.GOOD -> R.color.success
            Tone.INFO -> R.color.primary
            Tone.WARN -> R.color.warning
            Tone.BAD -> R.color.error
            Tone.HEAT_LOW, Tone.HEAT_MID, Tone.HEAT_HIGH -> R.color.on_primary_container
        },
    )

    /** Подсветка величины — фоном, как в диспетчере задач: чем больше, тем плотнее. */
    private fun heat(t: Tone): Int {
        val alpha = when (t) {
            Tone.HEAT_LOW -> 0x55
            Tone.HEAT_MID -> 0xAA
            Tone.HEAT_HIGH -> 0xFF
            else -> return 0
        }
        return (context.getColor(R.color.primary_container) and 0x00FFFFFF) or (alpha shl 24)
    }

    private inner class LiveModel(private val data: List<ConnectionRow>) : GridTable.Model {
        override val columns: List<GridTable.Column> get() = liveColumns
        override val rows: Int get() = data.size
        override val sortColumn: Int get() = LIVE.indexOf(sort.column)
        override val sortDescending: Boolean get() = sort.descending

        override fun text(row: Int, col: Int): String = ConnectionCells.text(data[row], LIVE[col], labels, ::app)

        override fun color(row: Int, col: Int): Int = color(ConnectionTable.tone(data[row], LIVE[col]), ConnectionTable.rowTone(data[row]))

        override fun background(row: Int, col: Int): Int = heat(ConnectionTable.tone(data[row], LIVE[col]))

        override fun stripe(row: Int): Int = context.getColor(
            when (data[row].state) {
                ConnState.OPEN -> R.color.success
                ConnState.CLOSED -> R.color.outline_strong
                ConnState.FAILED -> R.color.error
            },
        )

        override fun describe(row: Int): String = SPOKEN.joinToString(", ") { col ->
            context.getString(title(col)) + ": " + ConnectionCells.text(data[row], col, labels, ::app)
        }
    }

    private inner class UniqueModel(private val data: List<UniqueEntry>) : GridTable.Model {
        override val columns: List<GridTable.Column> get() = uniqueColumns
        override val rows: Int get() = data.size
        override val sortColumn: Int get() = UNIQUE.indexOf(uniqueSort.column)
        override val sortDescending: Boolean get() = uniqueSort.descending

        override fun text(row: Int, col: Int): String = ConnectionCells.unique(data[row], UNIQUE[col], labels, ::dateTime, ::app)

        override fun color(row: Int, col: Int): Int =
            context.getColor(if (UNIQUE[col] == UniqueColumn.APP && data[row].key.app == null) R.color.text_secondary else R.color.text)

        override fun background(row: Int, col: Int): Int = 0

        override fun stripe(row: Int): Int = 0

        override fun describe(row: Int): String = UNIQUE.joinToString(", ") { col ->
            context.getString(title(col)) + ": " + ConnectionCells.unique(data[row], col, labels, ::dateTime, ::app)
        }
    }

    companion object {
        const val TAB_LIVE: Int = 0
        const val TAB_JOURNAL: Int = 1
        private const val TICK_MILLIS = 1_000L

        /** Порядок столбцов на телефоне: адрес закреплён слева, дальше — то, что важнее увидеть сразу. */
        val LIVE: List<ConnColumn> = listOf(
            ConnColumn.HOST, ConnColumn.STATE, ConnColumn.APP, ConnColumn.DOWN_RATE, ConnColumn.UP_RATE, ConnColumn.DOWN_BYTES,
            ConnColumn.UP_BYTES, ConnColumn.FIRST_BYTE, ConnColumn.RELIABILITY, ConnColumn.RECENT, ConnColumn.DURATION, ConnColumn.IDLE,
            ConnColumn.ROUTE, ConnColumn.PROTOCOL, ConnColumn.NETWORK, ConnColumn.PORT, ConnColumn.INBOUND, ConnColumn.DOWN_CHUNKS,
            ConnColumn.UP_CHUNKS,
        )
        val UNIQUE: List<UniqueColumn> =
            listOf(UniqueColumn.HOST, UniqueColumn.APP, UniqueColumn.PORT, UniqueColumn.NETWORK, UniqueColumn.COUNT, UniqueColumn.LAST)

        /** Что TalkBack произносит у строки — главное, без всех 19 столбцов. */
        private val SPOKEN = listOf(ConnColumn.HOST, ConnColumn.STATE, ConnColumn.APP, ConnColumn.DOWN_RATE, ConnColumn.UP_RATE, ConnColumn.FIRST_BYTE)

        fun title(c: ConnColumn): Int = when (c) {
            ConnColumn.STATE -> R.string.conn_col_state
            ConnColumn.APP -> R.string.conn_col_app
            ConnColumn.HOST -> R.string.conn_col_host
            ConnColumn.PORT -> R.string.conn_col_port
            ConnColumn.NETWORK -> R.string.conn_col_network
            ConnColumn.PROTOCOL -> R.string.conn_col_protocol
            ConnColumn.ROUTE -> R.string.conn_col_route
            ConnColumn.INBOUND -> R.string.conn_col_inbound
            ConnColumn.DURATION -> R.string.conn_col_duration
            ConnColumn.IDLE -> R.string.conn_col_idle
            ConnColumn.FIRST_BYTE -> R.string.conn_col_first_byte
            ConnColumn.UP_RATE -> R.string.conn_col_up_rate
            ConnColumn.DOWN_RATE -> R.string.conn_col_down_rate
            ConnColumn.UP_BYTES -> R.string.conn_col_up_bytes
            ConnColumn.DOWN_BYTES -> R.string.conn_col_down_bytes
            ConnColumn.UP_CHUNKS -> R.string.conn_col_up_chunks
            ConnColumn.DOWN_CHUNKS -> R.string.conn_col_down_chunks
            ConnColumn.RECENT -> R.string.conn_col_recent
            ConnColumn.RELIABILITY -> R.string.conn_col_reliability
        }

        fun title(c: UniqueColumn): Int = when (c) {
            UniqueColumn.APP -> R.string.conn_col_app
            UniqueColumn.HOST -> R.string.conn_col_host
            UniqueColumn.PORT -> R.string.conn_col_port
            UniqueColumn.NETWORK -> R.string.conn_col_network
            UniqueColumn.COUNT -> R.string.conn_col_count
            UniqueColumn.LAST -> R.string.conn_col_last
        }
    }
}
