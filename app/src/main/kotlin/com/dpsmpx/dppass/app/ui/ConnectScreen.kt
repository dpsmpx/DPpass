package com.dpsmpx.dppass.app.ui

import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.Traffic
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.RoutingMode
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * «Подключение» (D-34, D-40): одна кнопка, состояние туннеля, время с
 * подключения, скорость и трафик сессии, выбранный сервер, режим
 * маршрутизации (D-38) и причина последнего отказа.
 */
class ConnectScreen(host: Host) : Screen(host) {
    private val source = Ui.text(context, R.style.Text_DPpass_Secondary).apply { gravity = Gravity.CENTER_HORIZONTAL }
    private val power = PowerButton(context)
    private val title = Ui.text(context, R.style.Text_DPpass_Headline).apply { gravity = Gravity.CENTER_HORIZONTAL }
    private val detail = Ui.text(context, R.style.Text_DPpass_Secondary).apply { gravity = Gravity.CENTER_HORIZONTAL }

    private val downSpeed = Ui.text(context, R.style.Text_DPpass_Title)
    private val downTotal = Ui.text(context, R.style.Text_DPpass_Caption)
    private val upSpeed = Ui.text(context, R.style.Text_DPpass_Title)
    private val upTotal = Ui.text(context, R.style.Text_DPpass_Caption)
    private val stats = Ui.card(context, 0).apply {
        val row = Ui.row(context)
        row.addView(stat(R.drawable.ic_down, R.string.traffic_down, downSpeed, downTotal), Ui.weight())
        row.addView(
            View(context).apply { setBackgroundColor(context.getColor(R.color.outline)) },
            LinearLayout.LayoutParams(maxOf(1, Ui.dp(context, 1)), Ui.dp(context, 40)).apply {
                marginStart = Ui.dp(context, 12)
                marginEnd = Ui.dp(context, 12)
            },
        )
        row.addView(stat(R.drawable.ic_up, R.string.traffic_up, upSpeed, upTotal), Ui.weight())
        addView(row, Ui.matchWidth())
    }

    private val serverAvatar = Ui.avatar(context, "•")

    /** «Автоматически» — тот же значок, что в списке серверов, а не буква. */
    private val autoAvatar = Ui.iconAvatar(context, R.drawable.ic_bolt)
    private val serverName = Ui.text(context, R.style.Text_DPpass_Body).apply {
        maxLines = 1
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val serverHint = Ui.text(context, R.style.Text_DPpass_Caption).apply {
        maxLines = 2
        ellipsize = android.text.TextUtils.TruncateAt.END
    }
    private val serverLatency = LinearLayout(context)
    private val serverCard = Ui.listCard(context).apply {
        val row = Ui.row(context).apply {
            setBackgroundResource(R.drawable.bg_row)
            isClickable = true
            isFocusable = true
            minimumHeight = Ui.dp(context, 64)
            setPadding(Ui.dp(context, 16), Ui.dp(context, 8), Ui.dp(context, 12), Ui.dp(context, 8))
            setOnClickListener { host.showTab(Host.TAB_SERVERS) }
            addView(serverAvatar)
            addView(autoAvatar)
            val texts = Ui.column(context, 2)
            texts.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.server_label)))
            texts.addView(serverName)
            texts.addView(serverHint)
            addView(texts, Ui.weight().apply { marginStart = Ui.dp(context, 12) })
            addView(serverLatency, Ui.wrap().apply { marginEnd = Ui.dp(context, 4) })
            addView(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        }
        addView(row, Ui.matchWidth())
        addView(Ui.divider(context, 16))
        addView(
            Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.routing_title))
                .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                .onClick { host.showTab(Host.TAB_SETTINGS) }
                .also { modeRow = it },
            Ui.matchWidth(),
        )
    }
    private lateinit var modeRow: Ui.ListRow

    private val failureTitle = Ui.text(context, R.style.Text_DPpass_Title).apply { setTextColor(context.getColor(R.color.error)) }
    private val failureText = Ui.text(context, R.style.Text_DPpass_Secondary).apply { setTextIsSelectable(true) }
    private val failureCard = Ui.card(context).apply {
        setBackgroundResource(R.drawable.bg_card)
        addView(failureTitle)
        addView(failureText)
        addView(Ui.button(context, R.string.open_log, Ui.Style.OUTLINE, R.drawable.ic_log).apply { setOnClickListener { host.push(LogScreen(host)) } })
    }

    private val emptyCard = Ui.card(context, 12).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        addView(
            Ui.icon(context, R.drawable.ic_subscriptions, R.color.primary, 40),
            LinearLayout.LayoutParams(Ui.dp(context, 40), Ui.dp(context, 40)).apply { gravity = Gravity.CENTER_HORIZONTAL },
        )
        addView(Ui.text(context, R.style.Text_DPpass_Title, context.getString(R.string.empty_title)).apply { gravity = Gravity.CENTER_HORIZONTAL }, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.empty_text)).apply { gravity = Gravity.CENTER_HORIZONTAL }, Ui.matchWidth())
        addView(
            Ui.button(context, R.string.subs_add, Ui.Style.PRIMARY, R.drawable.ic_add).apply { setOnClickListener { ImportFlow.addSubscription(host) } },
            Ui.matchWidth(),
        )
        addView(
            Ui.button(context, R.string.import_clipboard, Ui.Style.OUTLINE, R.drawable.ic_paste).apply { setOnClickListener { ImportFlow.fromClipboard(host) } },
            Ui.matchWidth(),
        )
    }

    override val view: View = scroll(
        Ui.column(context).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(header(context.getString(R.string.app_name), Ui.iconButton(context, R.drawable.ic_add, context.getString(R.string.add_title)) { ImportFlow.menu(host) }), Ui.matchWidth())
            addView(source, Ui.matchWidth())
            val size = Ui.dp(context, 184)
            addView(power, LinearLayout.LayoutParams(size, size).apply { topMargin = Ui.dp(context, 24) })
            addView(title, Ui.matchWidth().apply { topMargin = Ui.dp(context, 20) })
            addView(detail, Ui.matchWidth().apply { topMargin = Ui.dp(context, 4) })
            addView(stats, Ui.matchWidth().apply { topMargin = Ui.dp(context, 24) })
            addView(serverCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(failureCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(emptyCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 24) })
        },
        topDp = 4,
    )

    private var ticker: Job? = null

    private fun stat(icon: Int, label: Int, speed: TextView, total: TextView): LinearLayout = Ui.row(context).apply {
        addView(Ui.icon(context, icon, R.color.primary, 20))
        val texts = Ui.column(context, 2)
        texts.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(label)))
        texts.addView(speed)
        texts.addView(total)
        addView(texts, Ui.weight().apply { marginStart = Ui.dp(context, 8) })
    }

    override fun render(status: TunnelStatus) {
        val graph = host.graph
        val core = graph?.core
        val ir = core?.activation?.state?.activeConfig
        val hasServers = ir != null && ir.profiles.isNotEmpty()

        source.text = when (val s = ConfigSource.of(core?.activation?.state?.active?.source)) {
            ConfigSource.None -> context.getString(R.string.source_none)
            ConfigSource.Own -> context.getString(R.string.source_own)
            is ConfigSource.FromSubscription -> {
                val sub = (core?.subscriptions?.state() as? Outcome.Success)?.value?.find(s.id)
                val name = sub?.displayName ?: s.id.value
                context.getString(R.string.source_subscription, name)
            }
        }
        source.visibility = if (graph == null) View.INVISIBLE else View.VISIBLE

        power.apply(
            when {
                status is TunnelStatus.Connected -> PowerButton.Mode.CONNECTED
                status is TunnelStatus.Connecting -> PowerButton.Mode.CONNECTING
                status is TunnelStatus.Failed && hasServers -> PowerButton.Mode.FAILED
                status == TunnelStatus.Stopping || !hasServers -> PowerButton.Mode.DISABLED
                else -> PowerButton.Mode.OFF
            },
        )
        power.contentDescription = context.getString(if (status.busy) R.string.action_disconnect else R.string.action_connect)
        power.setOnClickListener { if (TunnelState.status.value.busy) host.disconnect() else host.connect() }

        title.setText(
            when (status) {
                TunnelStatus.Idle -> R.string.status_off
                is TunnelStatus.Connecting -> R.string.status_connecting
                is TunnelStatus.Connected -> R.string.status_connected
                TunnelStatus.Stopping -> R.string.status_stopping
                is TunnelStatus.Failed -> R.string.status_failed
            },
        )
        title.setTextColor(context.getColor(if (status is TunnelStatus.Connected) R.color.primary else R.color.text))
        renderDetail(status)
        renderTraffic(TunnelState.traffic.value, status)

        val chosen = ir?.let { c -> ServerList.effectiveSelection(c.profiles, host.prefs.selectedServer)?.let { id -> c.profiles.first { it.id == id } } }
        val connected = (status as? TunnelStatus.Connected)?.let { c -> ir?.profiles?.firstOrNull { it.id == c.profileId } }
        val shown = connected ?: chosen
        serverName.text = shown?.name?.let(Avatar::stripFlag) ?: context.getString(R.string.server_auto)
        serverHint.text = shown?.let(ServerList::summary) ?: context.getString(R.string.server_auto_hint)
        shown?.let { serverAvatar.text = Avatar.of(it.name) }
        serverAvatar.visibility = if (shown != null) View.VISIBLE else View.GONE
        autoAvatar.visibility = if (shown == null) View.VISIBLE else View.GONE
        serverLatency.removeAllViews()
        shown?.let { p -> Ui.latencyChip(context, LatencyLabel.of(core?.latency?.of(p.id)))?.let(serverLatency::addView) }
        serverCard.visibility = if (hasServers) View.VISIBLE else View.GONE

        val policy = core?.userPolicy?.currentOrDefault()
        val own = core?.activation?.state?.active?.source == com.dpsmpx.dppass.connection.PolicyService.OWN_DOCUMENT
        modeRow.subtitle(
            when {
                own -> context.getString(R.string.routing_own_document)
                policy?.mode == RoutingMode.RU_DIRECT -> context.getString(R.string.routing_ru_direct)
                else -> context.getString(R.string.routing_all)
            },
        )

        if (status is TunnelStatus.Failed) {
            failureTitle.setText(Ui.kind(status.reason.kind))
            failureText.text = status.reason.message
            failureCard.visibility = View.VISIBLE
        } else {
            failureCard.visibility = View.GONE
        }
        emptyCard.visibility = if (graph != null && !hasServers) View.VISIBLE else View.GONE
    }

    private fun renderDetail(status: TunnelStatus) {
        detail.text = when (status) {
            is TunnelStatus.Connecting -> status.profileName?.let { context.getString(R.string.status_checking, Avatar.stripFlag(it)) }.orEmpty()
            is TunnelStatus.Connected -> Formats.duration(Clock.MONOTONIC.nowMillis() - status.sinceMonotonic)
            else -> ""
        }
        detail.visibility = if (detail.text.isEmpty()) View.INVISIBLE else View.VISIBLE
    }

    private fun renderTraffic(t: Traffic, status: TunnelStatus) {
        stats.visibility = if (status is TunnelStatus.Connected) View.VISIBLE else View.GONE
        downSpeed.text = speed(t.downPerSec)
        upSpeed.text = speed(t.upPerSec)
        downTotal.text = context.getString(R.string.traffic_total, bytes(t.downBytes))
        upTotal.text = context.getString(R.string.traffic_total, bytes(t.upBytes))
        stats.contentDescription = context.getString(R.string.a11y_traffic, speed(t.downPerSec), speed(t.upPerSec))
    }

    override fun onShown() {
        ticker?.cancel()
        // Пока экран виден: время с подключения — каждую секунду, трафик — по мере прихода от сервиса.
        ticker = host.scope.launch {
            launch { TunnelState.traffic.collect { renderTraffic(it, TunnelState.status.value) } }
            while (isActive) {
                renderDetail(TunnelState.status.value)
                delay(1_000)
            }
        }
    }

    override fun onHidden() {
        ticker?.cancel()
        ticker = null
    }
}
