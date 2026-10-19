package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.text.InputType
import android.view.View
import android.view.inputmethod.EditorInfo
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.NetworkCheck
import com.dpsmpx.dppass.app.PlanSnapshot
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.ActivationRecord
import com.dpsmpx.dppass.connection.ActivationStatus
import com.dpsmpx.dppass.connection.ActivationStep
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.xray.Ipv6Egress
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Почему этот сервер» (D-15): последнее подключение — попытки по порядку
 * с причинами и исходами, исключённые с причинами; ниже — план следующего
 * подключения с теми же правилами. Причины — тексты планировщика как есть.
 */
class PlanScreen(host: Host) : SubScreen(host, R.string.plan_title) {
    private val last = Ui.column(context, 8)
    private val ipv6 = Ui.column(context, 8)
    private val next = Ui.column(context, 8)
    private var job: Job? = null

    override fun content(): View = Ui.column(context, 12).apply {
        addView(caption(R.string.plan_intro))
        addView(last, Ui.matchWidth())
        addView(ipv6, Ui.matchWidth())
        addView(Ui.section(context, context.getString(R.string.plan_next)))
        addView(next, Ui.matchWidth())
        addView(caption(R.string.plan_next_note))
    }

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        showLastPlan(core, TunnelState.plan.value)
        showIpv6(status)
        if (job?.isActive == true) return
        // Выбрано устройство раздачи (D-55): план — из одного кандидата, его и показывать.
        host.prefs.selectedRelay?.let { id ->
            next.removeAllViews()
            next.addView(note(context.getString(R.string.plan_next_relay, core.relays.find(id)?.name ?: id)))
            return
        }
        // План читает журнал здоровья и задержки — не на главном потоке.
        // Режим сети (D-64) — тот же, что возьмёт подключение: белый список по свежей проверке.
        job = host.scope.launch {
            val (regime, plan) = withContext(Dispatchers.IO) {
                val r = NetworkCheck.regime(context)
                r to core.plan(null, host.prefs.selectedServer, r)
            }
            showNextPlan(core, plan, regime != null)
            job = null
        }
    }

    override fun onShown() = render(TunnelState.status.value)

    override fun onHidden() {
        job?.cancel()
        job = null
    }

    private fun showLastPlan(core: DPpassCore, snapshot: PlanSnapshot?) {
        last.removeAllViews()
        if (snapshot == null) {
            last.addView(Ui.section(context, context.getString(R.string.plan_last)))
            last.addView(note(context.getString(R.string.plan_last_none)))
            return
        }
        last.addView(Ui.section(context, context.getString(R.string.plan_last_at, dateTime(snapshot.atMillis))))
        val name = names(core)
        last.addView(attemptsCard(PlanView.attempts(snapshot, name)), Ui.matchWidth())
        exclusionsCard(PlanView.excluded(snapshot.excluded, name))?.let { last.addView(it, Ui.matchWidth()) }
    }

    /**
     * Выпускает ли сервер сессии IPv6 (D-66) — строкой под последним
     * подключением, пока сессия та же. Маршрут и DNS от неё не меняются.
     */
    private fun showIpv6(status: TunnelStatus) {
        // Не «note»: так называется функция карточки ниже.
        val result = TunnelState.ipv6.value?.takeIf { status is TunnelStatus.Connected && it.profileId == status.profileId }
        ipv6.removeAllViews()
        if (result == null) return
        val name = (status as TunnelStatus.Connected).profileName
        val text = when (result.egress) {
            Ipv6Egress.FORWARDED -> R.string.plan_ipv6_forwarded
            Ipv6Egress.NOT_FORWARDED -> R.string.plan_ipv6_not_forwarded
            Ipv6Egress.UNKNOWN -> R.string.plan_ipv6_unknown
        }
        ipv6.addView(note(context.getString(text, name, dateTime(result.atMillis))))
    }

    private fun showNextPlan(core: DPpassCore, plan: ConnectionPlan?, underAllowlist: Boolean) {
        next.removeAllViews()
        if (underAllowlist) {
            val minutes = ((NetworkCheck.regimeAgeMillis() ?: 0) / 60_000).toInt()
            next.addView(note(context.resources.getQuantityString(R.plurals.plan_regime_allowlist, minutes, minutes)))
        }
        if (plan == null) {
            next.addView(note(context.getString(R.string.plan_next_none)))
            return
        }
        val name = names(core)
        if (plan.attempts.isEmpty()) {
            next.addView(note(plan.verdictMessage ?: context.getString(R.string.plan_next_empty)))
        } else {
            next.addView(attemptsCard(PlanView.preview(plan, name)), Ui.matchWidth())
        }
        exclusionsCard(PlanView.excluded(plan.excluded, name))?.let { next.addView(it, Ui.matchWidth()) }
    }

    private fun attemptsCard(rows: List<PlanRow>): View = Ui.listCard(context).apply {
        rows.forEachIndexed { i, r ->
            if (i > 0) addView(Ui.divider(context))
            val (icon, result) = when (val x = r.result) {
                PlanResult.Connected -> R.drawable.ic_check to context.getString(R.string.plan_connected)
                is PlanResult.Failed ->
                    R.drawable.ic_block to context.getString(R.string.error_with_reason, context.getString(Ui.kind(x.reason.kind)), x.reason.message)
                PlanResult.Planned -> R.drawable.ic_servers to null
            }
            // Код из журнала: в журнале у сервера код, а не имя (19.10.2026 автор не нашёл сервер из журнала).
            val lines = listOfNotNull(
                result,
                r.reasons.joinToString(ServerList.SEPARATOR).ifEmpty { null },
                context.getString(R.string.plan_journal_id, r.profileId.value),
            )
            val row = Ui.ListRow(context, icon, context.getString(R.string.plan_attempt, i + 1, r.name)).subtitle(lines.joinToString("\n"))
            row.subtitle.setTextIsSelectable(true)
            addView(row, Ui.matchWidth())
        }
    }

    private fun exclusionsCard(rows: List<PlanExclusion>): View? {
        if (rows.isEmpty()) return null
        return Ui.column(context, 8).apply {
            addView(
                Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.plan_excluded)).apply {
                    setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
                },
            )
            addView(
                Ui.listCard(context).apply {
                    rows.forEachIndexed { i, r ->
                        if (i > 0) addView(Ui.divider(context))
                        addView(Ui.ListRow(context, R.drawable.ic_block, r.name).subtitle(r.reason), Ui.matchWidth())
                    }
                },
                Ui.matchWidth(),
            )
        }
    }

    /** Имя сервера: из активной конфигурации или доверенного устройства (D-55), иначе — id. */
    private fun names(core: DPpassCore): (ProfileId) -> String {
        val profiles = core.activation.state.activeConfig?.profiles.orEmpty().associate { it.id to it.name }
        return { id ->
            profiles[id]?.let(Avatar::stripFlag)
                ?: id.value.takeIf { it.startsWith(RelayDevice.PROFILE_PREFIX) }?.let { core.relays.find(it.removePrefix(RelayDevice.PROFILE_PREFIX))?.name }
                ?: id.value
        }
    }

    private fun caption(text: Int): View = Ui.text(context, R.style.Text_DPpass_Caption, context.getString(text)).apply {
        setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
    }

    private fun note(text: CharSequence): View = Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Secondary, text)) }
}

/**
 * «История активаций» (D-07): каждая попытка применить конфигурацию —
 * версия, время, источник, сумма, исход и шаг, на котором отказала.
 * Хранится до 32 записей.
 */
class ActivationHistoryScreen(host: Host) : SubScreen(host, R.string.history_title) {
    private val list = Ui.column(context, 8)

    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.history_intro)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(list, Ui.matchWidth())
    }

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        val rows = ActivationHistory.rows(core.activation.state.history)
        list.removeAllViews()
        if (rows.isEmpty()) {
            list.addView(
                Ui.card(context).apply { addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.history_empty))) },
                Ui.matchWidth(),
            )
            return
        }
        val subs = (core.subscriptions.state() as? Outcome.Success)?.value
        list.addView(
            Ui.listCard(context).apply {
                rows.forEachIndexed { i, r ->
                    if (i > 0) addView(Ui.divider(context))
                    addView(historyRow(r) { id -> subs?.find(id)?.displayName ?: id.value }, Ui.matchWidth())
                }
            },
            Ui.matchWidth(),
        )
    }

    override fun onShown() = render(TunnelState.status.value)

    private fun historyRow(r: ActivationRecord, subscription: (SubscriptionId) -> String): View {
        val (icon, label) = when (r.status) {
            ActivationStatus.ACTIVE -> R.drawable.ic_check to R.string.history_active
            ActivationStatus.SUPERSEDED -> R.drawable.ic_clock to R.string.history_superseded
            ActivationStatus.REJECTED -> R.drawable.ic_block to R.string.history_rejected
            ActivationStatus.ROLLED_BACK -> R.drawable.ic_refresh to R.string.history_rolled_back
        }
        val source = when (val s = ActivationHistory.source(r.source)) {
            HistorySource.Own -> context.getString(R.string.source_own)
            is HistorySource.Subscription -> context.getString(R.string.source_subscription, subscription(s.id))
            is HistorySource.Rollback -> context.getString(R.string.history_rollback_from, s.fromRevision?.toString() ?: "?")
            is HistorySource.Other -> s.raw
        }
        val lines = mutableListOf(
            listOf(dateTime(r.timestampMillis), source).joinToString(ServerList.SEPARATOR),
            context.getString(R.string.history_checksum, ActivationHistory.shortChecksum(r.sourceChecksum)),
        )
        r.failedStep?.let { lines += context.getString(R.string.history_failed_step, context.getString(step(it))) }
        r.failure?.let { lines += it }
        val heading = context.getString(R.string.history_revision, r.revision, context.getString(label))
        return Ui.ListRow(context, icon, heading).subtitle(lines.joinToString("\n")).apply {
            subtitle.setTextIsSelectable(true)
            if (r.status == ActivationStatus.REJECTED) title.setTextColor(context.getColor(R.color.error))
        }
    }

    private fun step(s: ActivationStep): Int = when (s) {
        ActivationStep.VALIDATION -> R.string.step_validation
        ActivationStep.CAPABILITY -> R.string.step_capability
        ActivationStep.COMPILE -> R.string.step_compile
        ActivationStep.BACKEND_VALIDATION -> R.string.step_backend_validation
        ActivationStep.HEALTH_CHECK -> R.string.step_health_check
        ActivationStep.COMMIT -> R.string.step_commit
    }
}

/**
 * «Почему этот маршрут» (D-09): сайт, адрес или ссылка и, по желанию,
 * приложение → куда пойдёт соединение по активной конфигурации и по
 * какому правилу. Решает ядро на своих геоданных (D-27), как в туннеле.
 */
class RouteCheckScreen(host: Host) : SubScreen(host, R.string.route_title) {
    private val input = Ui.field(context, R.string.route_hint, InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI).apply {
        imeOptions = EditorInfo.IME_ACTION_DONE
        setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE) runCheck()
            action == EditorInfo.IME_ACTION_DONE
        }
    }
    private var app: AppEntry? = null
    private val appRow = Ui.ListRow(context, R.drawable.ic_apps, context.getString(R.string.route_app))
        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
        .onClick { pickApp() }
    private val checkButton = Ui.button(context, R.string.route_check, Ui.Style.PRIMARY, R.drawable.ic_search)
    private val verdictTitle = Ui.text(context, R.style.Text_DPpass_Title)
    private val verdictText = Ui.text(context, R.style.Text_DPpass_Secondary).apply { setTextIsSelectable(true) }
    private val verdict = Ui.card(context).apply {
        addView(verdictTitle)
        addView(verdictText)
        visibility = View.GONE
    }
    private var job: Job? = null

    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.route_intro)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(input, Ui.matchWidth())
        addView(Ui.listCard(context).apply { addView(appRow, Ui.matchWidth()) }, Ui.matchWidth())
        addView(checkButton.apply { setOnClickListener { runCheck() } }, Ui.matchWidth())
        addView(verdict, Ui.matchWidth())
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.route_note)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
    }

    override fun render(status: TunnelStatus) {
        appRow.subtitle(app?.label ?: context.getString(R.string.route_app_any))
    }

    override fun onShown() = render(TunnelState.status.value)

    override fun onHidden() {
        job?.cancel()
        job = null
        checkButton.isEnabled = true
    }

    private fun pickApp() {
        host.scope.launch {
            val apps = withContext(Dispatchers.IO) { launcherApps(context) }
            val labels = listOf(context.getString(R.string.route_app_any)) + apps.map { it.label }
            Ui.secure(
                AlertDialog.Builder(context)
                    .setTitle(R.string.route_app)
                    .setItems(labels.toTypedArray()) { _, which ->
                        app = apps.getOrNull(which - 1)
                        render(TunnelState.status.value)
                    }
                    .create(),
            ).show()
        }
    }

    private fun runCheck() {
        val core = host.graph?.core ?: return
        if (job?.isActive == true) return
        val query = RouteExplain.query(input.text.toString(), app?.packageName)
        if (query == null) {
            host.toast(context.getString(R.string.route_bad_input))
            return
        }
        val policy = core.activation.state.activeConfig?.routing
        if (policy == null) {
            host.toast(context.getString(R.string.route_no_config))
            return
        }
        RouteExplain.localBypass(query, policy)?.let {
            showAnswer(it)
            return
        }
        checkButton.isEnabled = false
        job = host.scope.launch {
            try {
                // Список «Напрямую с разбиением» (D-72) сильнее документа — его ядро проверяет первым.
                val sites = host.prefs.splitSites()
                when (val s = withContext(Dispatchers.IO) { core.matchesSplitSites(query, sites) }) {
                    is Outcome.Failure -> {
                        host.problem(context.getString(R.string.route_failed), s.errors.first())
                        return@launch
                    }
                    is Outcome.Success -> if (s.value) {
                        showAnswer(RouteAnswer(RouteVerdict.DIRECT, RouteWhy.SplitSites))
                        return@launch
                    }
                }
                // Первое обращение к geosite/geoip читает файл набора — не на главном потоке.
                when (val r = withContext(Dispatchers.IO) { core.explain(query) }) {
                    null -> host.toast(context.getString(R.string.route_no_config))
                    is Outcome.Success -> showAnswer(RouteExplain.answer(r.value, query, policy))
                    is Outcome.Failure -> host.problem(context.getString(R.string.route_failed), r.errors.first())
                }
            } finally {
                checkButton.isEnabled = true
                job = null
            }
        }
    }

    private fun showAnswer(a: RouteAnswer) {
        val (title, color) = when (a.verdict) {
            RouteVerdict.TUNNEL -> R.string.route_tunnel to R.color.primary
            RouteVerdict.DIRECT -> R.string.route_direct to R.color.text
            RouteVerdict.BLOCKED -> R.string.route_blocked to R.color.error
        }
        verdictTitle.setText(title)
        verdictTitle.setTextColor(context.getColor(color))
        verdictText.text = when (val w = a.why) {
            RouteWhy.Ads -> context.getString(R.string.route_why_ads)
            RouteWhy.RuSites -> context.getString(R.string.route_why_ru_sites)
            RouteWhy.RuIp -> context.getString(R.string.route_why_ru_ip)
            RouteWhy.AutoDomestic -> context.getString(R.string.route_why_auto)
            RouteWhy.AppOutside -> context.getString(R.string.route_why_app)
            RouteWhy.LocalNetwork -> context.getString(R.string.route_why_lan)
            RouteWhy.SplitSites -> context.getString(R.string.route_why_split_sites)
            RouteWhy.Default -> context.getString(R.string.route_why_default)
            is RouteWhy.DocumentRule -> context.getString(R.string.route_why_rule, w.id)
        }
        verdict.visibility = View.VISIBLE
    }
}
