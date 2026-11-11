package com.dpsmpx.dppass.app.ui

import android.view.Gravity
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DPpassVpnService
import com.dpsmpx.dppass.app.ServerOffer
import com.dpsmpx.dppass.app.Traffic
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.UsageAlerts
import com.dpsmpx.dppass.connection.LocalProxyOffer
import com.dpsmpx.dppass.connection.RoutingMode
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * «Подключение» (D-34, D-40): одна кнопка, состояние туннеля, время с
 * подключения, скорость и трафик сессии, выбранный сервер, режим
 * маршрутизации (D-38) и причина последнего отказа. Сбой выбранного
 * сервера (D-58) — вопрос «перейти?» карточкой: тот же, что в уведомлении,
 * и виден, даже если уведомления выключены.
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
    private val modeRow = Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.routing_title))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { host.showTab(Host.TAB_SETTINGS) }
    private val serverCard = Ui.listCard(context).apply {
        val row = Ui.row(context).apply {
            setBackgroundResource(R.drawable.bg_row)
            isClickable = true
            isFocusable = true
            minimumHeight = Ui.dp(context, 64)
            setPadding(Ui.dp(context, 16), Ui.dp(context, 8), Ui.dp(context, 12), Ui.dp(context, 8))
            // Через устройство раздачи (D-55) — его экран, иначе — серверы.
            setOnClickListener { if (host.prefs.selectedRelay != null) host.push(RelaysScreen(host)) else host.showTab(Host.TAB_SERVERS) }
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
        addView(modeRow, Ui.matchWidth())
        addView(Ui.divider(context, 16))
        addView(
            Ui.ListRow(context, R.drawable.ic_info, context.getString(R.string.plan_title))
                .subtitle(context.getString(R.string.plan_entry_note))
                .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                .onClick { host.push(PlanScreen(host)) },
            Ui.matchWidth(),
        )
    }

    /** Трафик через сервер (D-92): сегодня и за период; по нажатию — подробно и настройки. */
    private val usageRow = Ui.ListRow(context, R.drawable.ic_down, context.getString(R.string.usage_title))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { host.push(UsageScreen(host)) }

    /** Анализатор соединений (D-106): таблица соединений и журнал уникальных. */
    private val connectionsRow = Ui.ListRow(context, R.drawable.ic_speed, context.getString(R.string.conn_title))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { host.push(ConnectionsScreen(host)) }
    private val usageCard = Ui.listCard(context).apply {
        addView(usageRow, Ui.matchWidth())
        addView(Ui.divider(context, 16))
        addView(connectionsRow, Ui.matchWidth())
    }

    private val failureTitle = Ui.text(context, R.style.Text_DPpass_Title).apply { setTextColor(context.getColor(R.color.error)) }
    private val failureText = Ui.text(context, R.style.Text_DPpass_Secondary).apply { setTextIsSelectable(true) }

    /** VPN не поднялся (D-95): подключиться без VPN — по нажатию. */
    private val failureOffer = Ui.button(context, R.string.local_proxy_offer, Ui.Style.PRIMARY, R.drawable.ic_route).apply {
        setOnClickListener { host.connectWithoutVpn() }
    }
    private val failureCard = Ui.card(context).apply {
        setBackgroundResource(R.drawable.bg_card)
        addView(failureTitle)
        addView(failureText)
        addView(failureOffer, Ui.matchWidth())
        addView(Ui.button(context, R.string.open_log, Ui.Style.OUTLINE, R.drawable.ic_log).apply { setOnClickListener { host.push(LogScreen(host)) } })
    }

    /** Подключение без VPN (D-95): адрес прокси для приложений; по нажатию — логин, пароль и настройки. */
    private val localProxyRow = Ui.ListRow(context, R.drawable.ic_route, context.getString(R.string.local_proxy_title))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { host.push(LocalProxyScreen(host)) }
    private val localProxyCard = Ui.listCard(context).apply { addView(localProxyRow, Ui.matchWidth()) }

    private val offerText = Ui.text(context, R.style.Text_DPpass_Secondary)
    private val offerSwitch = Ui.button(context, R.string.action_switch, Ui.Style.PRIMARY, R.drawable.ic_bolt)
    private val offerCard = Ui.card(context).apply {
        setBackgroundResource(R.drawable.bg_card)
        addView(Ui.text(context, R.style.Text_DPpass_Title, context.getString(R.string.switch_title)).apply { setTextColor(context.getColor(R.color.warning)) })
        addView(offerText)
        addView(offerSwitch, Ui.matchWidth())
        addView(Ui.button(context, R.string.action_keep, Ui.Style.TEXT).apply { setOnClickListener { offer?.let { keep(it) } } }, Ui.matchWidth())
    }

    /** Вопрос, на который отвечают кнопки карточки (D-58). */
    private var offer: ServerOffer? = null

    /** Без сервера (D-73): серверов нет, а туннель для сайтов списка поднимается. */
    private val serverlessRow = Ui.ListRow(context, R.drawable.ic_shield, context.getString(R.string.serverless_name))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { host.showTab(Host.TAB_SETTINGS) }
    private val serverlessCard = Ui.listCard(context).apply { addView(serverlessRow, Ui.matchWidth()) }

    private val emptyCard = Ui.card(context, 12).apply {
        gravity = Gravity.CENTER_HORIZONTAL
        addView(
            Ui.icon(context, R.drawable.ic_subscriptions, R.color.primary, 40),
            LinearLayout.LayoutParams(Ui.dp(context, 40), Ui.dp(context, 40)).apply { gravity = Gravity.CENTER_HORIZONTAL },
        )
        addView(
            Ui.text(context, R.style.Text_DPpass_Title, context.getString(R.string.empty_title)).apply { gravity = Gravity.CENTER_HORIZONTAL },
            Ui.matchWidth(),
        )
        addView(
            Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.empty_text)).apply { gravity = Gravity.CENTER_HORIZONTAL },
            Ui.matchWidth(),
        )
        addView(
            Ui.button(context, R.string.subs_add, Ui.Style.PRIMARY, R.drawable.ic_add).apply { setOnClickListener { ImportFlow.addSubscription(host) } },
            Ui.matchWidth(),
        )
        addView(
            Ui.button(context, R.string.import_clipboard, Ui.Style.OUTLINE, R.drawable.ic_paste).apply {
                setOnClickListener { ImportFlow.fromClipboard(host) }
            },
            Ui.matchWidth(),
        )
        addView(
            Ui.button(context, R.string.relays_entry, Ui.Style.TEXT, R.drawable.ic_lan).apply { setOnClickListener { host.push(RelaysScreen(host)) } },
            Ui.matchWidth(),
        )
    }

    override val view: View = scroll(
        Ui.column(context).apply {
            gravity = Gravity.CENTER_HORIZONTAL
            addView(
                header(
                    context.getString(R.string.app_name),
                    Ui.iconButton(context, R.drawable.ic_add, context.getString(R.string.add_title)) {
                        ImportFlow.menu(host)
                    },
                ),
                Ui.matchWidth(),
            )
            addView(source, Ui.matchWidth())
            val size = Ui.dp(context, 184)
            addView(power, LinearLayout.LayoutParams(size, size).apply { topMargin = Ui.dp(context, 24) })
            addView(title, Ui.matchWidth().apply { topMargin = Ui.dp(context, 20) })
            addView(detail, Ui.matchWidth().apply { topMargin = Ui.dp(context, 4) })
            addView(stats, Ui.matchWidth().apply { topMargin = Ui.dp(context, 24) })
            addView(offerCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(serverCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(usageCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(failureCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(serverlessCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
            addView(localProxyCard, Ui.matchWidth().apply { topMargin = Ui.dp(context, 16) })
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
        // Выбрано устройство раздачи (D-55) — подключаться есть к чему и без подписки.
        val relay = host.prefs.selectedRelay?.let { id -> core?.relays?.find(id) }
        val hasServers = relay != null || (ir != null && ir.profiles.isNotEmpty())
        // Без сервера (D-73): серверов нет, но сайтам списка туннель нужен — кнопка доступна.
        val sites = host.prefs.splitSites()
        val serverless = host.prefs.serverless
        val serverlessReady = core?.serverlessReady(sites, serverless, relaySelected = relay != null) == true
        val canConnect = hasServers || serverlessReady

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
                status is TunnelStatus.Failed && status.trafficBlocked -> PowerButton.Mode.FAILED
                status is TunnelStatus.Failed && canConnect -> PowerButton.Mode.FAILED
                status == TunnelStatus.Stopping || !canConnect -> PowerButton.Mode.DISABLED
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
                is TunnelStatus.Failed -> if (status.trafficBlocked) R.string.status_blocked else R.string.status_failed
            },
        )
        title.setTextColor(context.getColor(if (status is TunnelStatus.Connected) R.color.primary else R.color.text))
        renderDetail(status)
        renderTraffic(TunnelState.traffic.value, status)
        renderUsage()

        val chosen = ir?.let { c -> ServerList.effectiveSelection(c.profiles, host.prefs.selectedServer)?.let { id -> c.profiles.first { it.id == id } } }
        val connected = (status as? TunnelStatus.Connected)?.let { c -> ir?.profiles?.firstOrNull { it.id == c.profileId } }
        val shown = if (relay != null) null else connected ?: chosen
        serverName.text = relay?.name ?: shown?.name?.let(Avatar::stripFlag) ?: context.getString(R.string.server_auto)
        serverHint.text = if (relay != null) {
            context.getString(R.string.relays_summary)
        } else {
            shown?.let(ServerList::summary) ?: context.getString(R.string.server_auto_hint)
        }
        (relay?.name ?: shown?.name)?.let { serverAvatar.text = Avatar.of(it) }
        serverAvatar.visibility = if (relay != null || shown != null) View.VISIBLE else View.GONE
        autoAvatar.visibility = if (relay == null && shown == null) View.VISIBLE else View.GONE
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

        val withoutVpn = core?.localProxy?.current()?.valueOrNull()?.takeIf { it.enabled }
        if (status is TunnelStatus.Failed) {
            failureTitle.setText(Ui.kind(status.reason.kind))
            failureText.text = status.reason.message + if (status.trafficBlocked) "\n" + context.getString(R.string.vpn_blocked_note) else ""
            failureOffer.visibility = if (LocalProxyOffer.applies(status.reason, withoutVpn != null)) View.VISIBLE else View.GONE
            failureCard.visibility = View.VISIBLE
        } else {
            failureCard.visibility = View.GONE
        }
        localProxyCard.visibility = if (withoutVpn != null) View.VISIBLE else View.GONE
        withoutVpn?.let { p ->
            val port = TunnelState.localProxy.value?.port ?: p.port
            val line = if (status is TunnelStatus.Connected) R.string.local_proxy_row_connected else R.string.local_proxy_row_on
            localProxyRow.subtitle(context.getString(line, port))
        }
        serverlessCard.visibility = if (serverlessReady) View.VISIBLE else View.GONE
        serverlessRow.subtitle(
            if (serverless.rest == ServerlessSettings.Rest.SPLIT) {
                context.getString(R.string.serverless_summary_split, sites.size)
            } else {
                context.getString(R.string.serverless_summary_direct, sites.size)
            },
        )
        emptyCard.visibility = if (graph != null && !hasServers) View.VISIBLE else View.GONE
        renderOffer(TunnelState.offer.value)
    }

    private fun renderOffer(next: ServerOffer?) {
        offer = next
        offerCard.visibility = if (next == null) View.GONE else View.VISIBLE
        next ?: return
        val locale = context.resources.configuration.locales[0]
        val kind = context.getString(Ui.kind(next.reason.kind)).replaceFirstChar { it.lowercase(locale) }
        offerText.text = context.getString(R.string.switch_ask_text, next.fromName, kind, next.toName)
        offerSwitch.text = context.getString(R.string.action_switch_to, next.toName)
        offerSwitch.setOnClickListener { context.startForegroundService(DPpassVpnService.switchIntent(context, next.toId)) }
    }

    private fun keep(o: ServerOffer) {
        context.startService(DPpassVpnService.keepIntent(context, o.fromId))
    }

    private fun renderDetail(status: TunnelStatus) {
        detail.text = when (status) {
            is TunnelStatus.Connecting -> status.profileName?.let { context.getString(R.string.status_checking, Avatar.stripFlag(it)) }.orEmpty()
            is TunnelStatus.Connected -> Formats.duration(Clock.MONOTONIC.nowMillis() - status.sinceMonotonic)
            else -> ""
        }
        detail.visibility = if (detail.text.isEmpty()) View.INVISIBLE else View.VISIBLE
    }

    /** «Сегодня 120 МБ · с 1 окт. — 3,2 ГБ · мобильная 2,1 из 15 ГБ». */
    private fun renderUsage() {
        val core = host.graph?.core
        usageCard.visibility = if (core == null) View.GONE else View.VISIBLE
        val s = core?.usage?.summary() ?: return
        val line = context.getString(R.string.usage_row, bytes(s.todayTotal.total), UsageAlerts.date(context, s.periodStart), bytes(s.periodTotal.total))
        val limit = s.settings.mobileLimitBytes?.let { context.getString(R.string.usage_row_limit, bytes(s.mobilePeriodBytes), bytes(it)) }
        usageRow.subtitle(listOfNotNull(line, limit).joinToString(ServerList.SEPARATOR))
        connectionsRow.subtitle(context.getString(if (core.analyzer.settings().enabled) R.string.conn_entry_on else R.string.conn_entry_off))
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
            launch {
                TunnelState.traffic.collect {
                    renderTraffic(it, TunnelState.status.value)
                    renderUsage()
                }
            }
            launch { TunnelState.offer.collect { renderOffer(it) } }
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
