package com.dpsmpx.dppass.app.ui

import android.os.Build
import android.text.TextUtils
import android.view.View
import android.widget.LinearLayout
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.network.TcpLatencyProbe
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Серверы»: серверы активной конфигурации, выбор пользователя (D-34),
 * здоровье с запуска процесса (D-15) и задержка по замеру (D-41). Поиск
 * по имени и порядок — «как у поставщика» или «по задержке».
 */
class ServersScreen(host: Host) : Screen(host) {
    private val count = Ui.text(context, R.style.Text_DPpass_Secondary)
    private val relayNote = Ui.text(context, R.style.Text_DPpass_Secondary)
    private val list = Ui.listCard(context)
    private val empty = Ui.card(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Body, context.getString(R.string.servers_empty)))
        addView(Ui.button(context, R.string.add_title, Ui.Style.TONAL, R.drawable.ic_add).apply { setOnClickListener { ImportFlow.menu(host) } })
    }
    private var query = ""
    private var byLatency = false
    private var measuring: Job? = null

    private val measureButton = Ui.iconButton(context, R.drawable.ic_speed, context.getString(R.string.latency_check), R.color.primary) { measure() }
    private val sortRow = LinearLayout(context)
    private var measured = 0
    private var total = 0
    private val search = Ui.searchField(context, R.string.servers_search) { q ->
        query = q
        renderList(lastStatus)
    }
    private var lastStatus: TunnelStatus = TunnelStatus.Idle

    override val view: View = scroll(
        Ui.column(context, 12).apply {
            addView(
                header(
                    context.getString(R.string.tab_servers),
                    measureButton,
                    Ui.iconButton(context, R.drawable.ic_lan, context.getString(R.string.relays_entry)) { host.push(RelaysScreen(host)) },
                    Ui.iconButton(context, R.drawable.ic_add, context.getString(R.string.add_title)) { ImportFlow.menu(host) },
                ),
            )
            addView(count)
            addView(relayNote, Ui.matchWidth())
            addView(search, Ui.matchWidth())
            addView(sortRow, Ui.matchWidth())
            addView(list, Ui.matchWidth())
            addView(empty, Ui.matchWidth())
            addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.latency_note)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
        },
        topDp = 4,
    )

    override fun render(status: TunnelStatus) {
        lastStatus = status
        sortRow.removeAllViews()
        sortRow.addView(
            Ui.segmented(context, listOf(context.getString(R.string.sort_provider), context.getString(R.string.sort_latency)), if (byLatency) 1 else 0) {
                byLatency = it == 1
                render(lastStatus)
            },
            Ui.matchWidth(),
        )
        renderList(status)
    }

    private fun renderList(status: TunnelStatus) {
        val core = host.graph?.core
        val profiles = core?.activation?.state?.activeConfig?.profiles.orEmpty()
        list.removeAllViews()
        empty.visibility = if (core != null && profiles.isEmpty()) View.VISIBLE else View.GONE
        list.visibility = if (profiles.isEmpty()) View.GONE else View.VISIBLE
        search.visibility = if (profiles.size > SEARCH_FROM) View.VISIBLE else View.GONE
        val busy = measuring?.isActive == true
        measureButton.isEnabled = profiles.isNotEmpty() && !busy
        measureButton.alpha = if (measureButton.isEnabled) 1f else 0.5f
        val servers = context.resources.getQuantityString(R.plurals.servers_count, profiles.size, profiles.size)
        count.text = if (busy) context.getString(R.string.latency_progress, servers, measured, total) else servers
        // Выбрано устройство раздачи (D-55): выбор сервера здесь вернёт подключение к серверам.
        val relay = host.prefs.selectedRelay?.let { id -> core?.relays?.find(id) }
        relayNote.text = relay?.let { context.getString(R.string.servers_via_relay, it.name) }.orEmpty()
        relayNote.visibility = if (relay != null) View.VISIBLE else View.GONE
        if (core == null || profiles.isEmpty()) return
        val connected = (status as? TunnelStatus.Connected)?.profileId
        val all = ServerList.rows(profiles, core.health::of, host.prefs.selectedServer, connected, Clock.SYSTEM.nowMillis(), core.latency::of)
        val filtered = ServerList.filter(all, query)
        val rows = if (byLatency) ServerList.byLatency(filtered) else filtered
        if (query.isBlank()) {
            list.addView(row(null, "A", context.getString(R.string.server_auto), context.getString(R.string.server_auto_hint), null, LatencyLabel.UNKNOWN, rows.none { it.selected }, false))
        }
        for (r in rows) {
            list.addView(Ui.divider(context, 72))
            list.addView(row(r.id, r.avatar, Avatar.stripFlag(r.name), r.summary, state(r), r.latency, r.selected, r.connected))
        }
        if (rows.isEmpty()) list.addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.servers_not_found)).apply { setPadding(Ui.dp(context, 16), Ui.dp(context, 16), Ui.dp(context, 16), Ui.dp(context, 16)) })
    }

    private fun state(r: ServerRow): Triple<String, Int, Int>? = when (r.health) {
        RowHealth.UNKNOWN -> null
        RowHealth.HEALTHY -> Triple(context.getString(R.string.server_state_ok), R.color.success_container, R.color.success)
        RowHealth.FAILED -> Triple(
            context.getString(R.string.server_state_failed, r.lastFailure?.let { context.getString(Ui.kind(it)) }.orEmpty()),
            R.color.error_container,
            R.color.error,
        )
        RowHealth.PAUSED -> Triple(
            context.getString(R.string.server_state_paused, r.pauseSeconds.toInt(), r.lastFailure?.let { context.getString(Ui.kind(it)) }.orEmpty()),
            R.color.warning_container,
            R.color.warning,
        )
    }

    private fun row(
        id: ProfileId?,
        avatar: String,
        name: String,
        summary: String,
        state: Triple<String, Int, Int>?,
        latency: LatencyLabel,
        selected: Boolean,
        connected: Boolean,
    ): View = Ui.row(context).apply {
        setBackgroundResource(R.drawable.bg_row)
        setPadding(Ui.dp(context, 16), Ui.dp(context, 10), Ui.dp(context, 12), Ui.dp(context, 10))
        minimumHeight = Ui.dp(context, 64)
        isClickable = true
        isFocusable = true
        isSelected = selected
        addView(if (id == null) Ui.iconAvatar(context, R.drawable.ic_bolt) else Ui.avatar(context, avatar))
        val texts = Ui.column(context, 2)
        texts.addView(
            Ui.text(context, R.style.Text_DPpass_Body, name).apply {
                maxLines = 1
                ellipsize = TextUtils.TruncateAt.END
            },
        )
        texts.addView(Ui.text(context, R.style.Text_DPpass_Caption, summary).apply { maxLines = 2 })
        val chips = Ui.row(context, 6)
        if (connected) chips.addView(Ui.chip(context, context.getString(R.string.server_connected), R.color.primary_container, R.color.on_primary_container))
        if (state != null) chips.addView(Ui.chip(context, state.first, state.second, state.third))
        if (chips.childCount > 0) texts.addView(chips, Ui.wrap().apply { topMargin = Ui.dp(context, 4) })
        addView(texts, Ui.weight().apply { marginStart = Ui.dp(context, 12) })
        Ui.latencyChip(context, latency)?.let { addView(it, Ui.wrap().apply { marginStart = Ui.dp(context, 8) }) }
        addView(
            Ui.icon(context, if (selected) R.drawable.ic_radio_on else R.drawable.ic_radio_off, if (selected) R.color.primary else R.color.text_secondary),
            LinearLayout.LayoutParams(Ui.dp(context, 24), Ui.dp(context, 24)).apply { marginStart = Ui.dp(context, 8) },
        )
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) stateDescription = if (selected) context.getString(R.string.a11y_selected) else null
        setOnClickListener { choose(id) }
    }

    /**
     * Выбор сохраняется; если туннель есть или поднимается — переподключение к
     * выбранному. Выбор сервера — это и отказ от устройства раздачи (D-55).
     */
    private fun choose(id: ProfileId?) {
        if (id == host.prefs.selectedServer && host.prefs.selectedRelay == null) return
        host.prefs.selectedServer = id
        host.prefs.selectedRelay = null
        host.reconnectIfBusy()
        host.changed()
    }

    /** Задержка (D-41): только по нажатию, по одному серверу, с паузой; итоги — по мере замеров. */
    private fun measure() {
        val core = host.graph?.core ?: return
        val profiles = core.activation.state.activeConfig?.profiles.orEmpty()
        if (profiles.isEmpty() || measuring?.isActive == true) return
        measured = 0
        total = minOf(profiles.size, com.dpsmpx.dppass.connection.LatencyBook.MAX_PER_RUN)
        measuring = host.scope.launch {
            renderList(lastStatus)
            withContext(Dispatchers.IO) {
                core.latency.measureAll(profiles, TcpLatencyProbe(Clock.MONOTONIC), { delay(it) }) { _, _ ->
                    host.scope.launch {
                        measured++
                        renderList(lastStatus)
                    }
                }
            }
            measuring = null
            byLatency = true
            render(lastStatus)
        }
    }

    private companion object {
        /** Поиск — только когда серверов больше, чем помещается на экран. */
        const val SEARCH_FROM = 6
    }
}
