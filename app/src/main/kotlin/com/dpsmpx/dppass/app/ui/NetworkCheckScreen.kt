package com.dpsmpx.dppass.app.ui

import android.view.View
import android.widget.Button
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.NetworkCheck
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.RegimeMemory
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.xray.SpeedReport
import com.dpsmpx.dppass.network.Confidence
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

/**
 * «Проверка сети» (D-60): по кнопке — пробы D-14 мимо туннеля, исход
 * каждой и класс сети с доводами. Итог только для сведения: в план
 * подключения он пока не идёт. Ниже — замер через туннель (D-61): пинг,
 * jitter и скорость загрузки через сервер, к которому подключён DPpass.
 *
 * После каждого замера — пауза: кнопка недоступна, на ней — сколько ещё
 * ждать. У проверки сети пауза — из бюджета проб D-14, у скорости — своя
 * ([NetworkCheck.speedReadyInMillis]).
 */
class NetworkCheckScreen(host: Host) : SubScreen(host, R.string.netcheck_title) {
    private val run: Button = Ui.button(context, R.string.netcheck_run, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val verdictTitle = Ui.text(context, R.style.Text_DPpass_Title)
    private val verdictText = Ui.text(context, R.style.Text_DPpass_Secondary).apply { setTextIsSelectable(true) }
    private val verdict = Ui.card(context).apply {
        addView(verdictTitle)
        addView(verdictText)
        visibility = View.GONE
    }
    private val probes = Ui.listCard(context).apply { visibility = View.GONE }
    private var job: Job? = null

    private val speedRun: Button = Ui.button(context, R.string.speed_run, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val speedHint = Ui.text(context, R.style.Text_DPpass_Caption)
    private val speedResult = Ui.text(context, R.style.Text_DPpass_Body).apply {
        setTextIsSelectable(true)
        visibility = View.GONE
    }
    private var speedJob: Job? = null
    private var ticker: Job? = null

    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.netcheck_intro)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(run.apply { setOnClickListener { start() } }, Ui.matchWidth())
        addView(verdict, Ui.matchWidth())
        addView(probes, Ui.matchWidth())
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.netcheck_note)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(Ui.section(context, context.getString(R.string.speed_section)))
        addView(
            Ui.card(context).apply {
                addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.speed_note)))
                addView(speedRun.apply { setOnClickListener { measureSpeed() } }, Ui.matchWidth())
                addView(speedHint)
                addView(speedResult)
            },
            Ui.matchWidth(),
        )
    }

    override fun render(status: TunnelStatus) {
        // Замер — только через поднятый туннель: иначе мерить нечего (D-61).
        val connected = status is TunnelStatus.Connected
        speedHint.text = if (connected) {
            context.getString(R.string.speed_via, Avatar.stripFlag((status as TunnelStatus.Connected).profileName))
        } else {
            context.getString(R.string.speed_needs_tunnel)
        }
        refreshButtons()
    }

    override fun onShown() {
        render(TunnelState.status.value)
        ticker?.cancel()
        // Отсчёт паузы на кнопках — раз в секунду, пока экран виден.
        ticker = host.scope.launch {
            while (isActive) {
                delay(1_000)
                refreshButtons()
            }
        }
    }

    /**
     * Кнопки по состоянию: идёт замер — «Проверяю…» (и проверка после смены
     * сети, D-67), пауза — «через N с» и недоступна, иначе — доступна
     * (скорость — только с поднятым туннелем).
     */
    private fun refreshButtons() {
        if (job?.isActive != true) {
            val wait = NetworkCheck.readyInMillis()
            val busy = NetworkCheck.busy()
            run.isEnabled = wait == 0L && !busy
            run.text = when {
                busy -> context.getString(R.string.netcheck_running)
                wait == 0L -> context.getString(R.string.netcheck_run)
                else -> context.getString(R.string.netcheck_run_wait, seconds(wait))
            }
        }
        if (speedJob?.isActive != true) {
            val wait = NetworkCheck.speedReadyInMillis()
            speedRun.isEnabled = wait == 0L && TunnelState.status.value is TunnelStatus.Connected
            speedRun.text = if (wait == 0L) context.getString(R.string.speed_run) else context.getString(R.string.speed_run_wait, seconds(wait))
        }
    }

    private fun seconds(millis: Long): Int = ((millis + 999) / 1000).toInt()

    override fun onHidden() {
        // Ушли с экрана — проверка и замер останавливаются: их никто не ждёт. Пауза остаётся.
        ticker?.cancel()
        ticker = null
        job?.cancel()
        job = null
        speedJob?.cancel()
        speedJob = null
        refreshButtons()
    }

    private fun measureSpeed() {
        val graph = host.graph ?: return
        val connected = TunnelState.status.value as? TunnelStatus.Connected ?: return
        if (speedJob?.isActive == true) return
        speedRun.isEnabled = false
        speedRun.setText(R.string.speed_running)
        speedResult.visibility = View.GONE
        speedJob = host.scope.launch {
            try {
                when (val r = NetworkCheck.speed(graph.engine, graph.core.log, connected.profileId)) {
                    null -> Unit
                    is Outcome.Success -> showSpeed(r.value)
                    is Outcome.Failure -> host.problem(context.getString(R.string.speed_failed), r.errors.first())
                }
            } finally {
                speedJob = null
                render(TunnelState.status.value)
            }
        }
    }

    private fun showSpeed(s: SpeedReport) {
        val locale = context.resources.configuration.locales[0]
        fun ms(v: Double) = String.format(locale, "%.0f", v)
        val mbps = String.format(locale, "%.1f", s.downloadBitsPerSecond / 1_000_000.0)
        val seconds = String.format(locale, "%.1f", s.transferMillis / 1000.0)
        val lines = mutableListOf(
            context.getString(R.string.speed_ping, ms(s.pingMillis), ms(s.minPingMillis), ms(s.jitterMillis)),
            context.getString(R.string.speed_download, mbps, bytes(s.receivedBytes), seconds),
        )
        // Данные встали посреди загрузки (L7): средняя — не скорость канала, это надо сказать.
        s.stalledAfterMillis?.let { after ->
            lines += context.getString(
                R.string.speed_stalled,
                String.format(locale, "%.1f", after / 1000.0),
                String.format(locale, "%.1f", s.activeBitsPerSecond / 1_000_000.0),
            )
        }
        speedResult.text = lines.joinToString("\n")
        speedResult.visibility = View.VISIBLE
    }

    private fun start() {
        val core = host.graph?.core ?: return
        if (job?.isActive == true) return
        // Повтор раньше бюджета дал бы пропуски вместо вывода: подождать (D-14, D-60).
        val wait = NetworkCheck.readyInMillis()
        if (wait > 0) {
            host.toast(context.getString(R.string.netcheck_wait, seconds(wait)))
            return
        }
        run.isEnabled = false
        run.setText(R.string.netcheck_running)
        verdict.visibility = View.GONE
        probes.removeAllViews()
        probes.visibility = View.VISIBLE
        job = host.scope.launch {
            try {
                val result = NetworkCheck.run(context, core.log) { r -> context.runOnUiThread { addProbe(r) } }
                if (result == null) {
                    // Уже идёт проверка после смены сети (D-67): вторая вперемешку упёрлась бы в бюджет.
                    host.toast(context.getString(R.string.netcheck_busy))
                    probes.visibility = View.GONE
                } else {
                    showVerdict(result)
                }
            } finally {
                // Проверка закончилась — на кнопке пауза до следующей (бюджет проб).
                job = null
                refreshButtons()
            }
        }
    }

    private fun addProbe(r: ProbeResult) {
        if (probes.childCount > 0) probes.addView(Ui.divider(context))
        val title = context.getString(R.string.netcheck_probe, context.getString(kind(r.request.kind)), context.getString(target(r.request.target)))
        val outcome = context.getString(outcome(r.outcome))
        val subtitle = r.latencyMillis?.let { context.getString(R.string.netcheck_probe_ms, outcome, it) } ?: outcome
        probes.addView(Ui.ListRow(context, if (r.ok) R.drawable.ic_check else R.drawable.ic_block, title).subtitle(subtitle), Ui.matchWidth())
    }

    private fun showVerdict(a: NetworkAssessment) {
        verdictTitle.text = context.getString(restriction(a.restriction))
        verdictTitle.setTextColor(context.getColor(if (a.restriction == RestrictionClass.NORMAL) R.color.primary else R.color.warning))
        val lines = listOf(
            context.getString(R.string.netcheck_network, context.getString(type(a.type))),
            context.getString(R.string.netcheck_confidence, context.getString(confidence(a.confidence))),
        ) + a.evidence.map { "• $it" } + listOfNotNull(
            // Итог запомнен для плана (D-64): под белым списком — первыми те, что под ним работали.
            if (a.restriction == RestrictionClass.ALLOWLIST_LIKE) {
                val minutes = (RegimeMemory.TTL_MILLIS / 60_000).toInt()
                context.resources.getQuantityString(R.plurals.netcheck_regime_saved, minutes, minutes)
            } else {
                null
            },
        )
        verdictText.text = lines.joinToString("\n")
        verdict.visibility = View.VISIBLE
        if (probes.childCount == 0) probes.visibility = View.GONE
    }

    private fun kind(k: ProbeKind): Int = when (k) {
        ProbeKind.DNS -> R.string.probe_dns
        ProbeKind.TCP -> R.string.probe_tcp
        ProbeKind.TLS -> R.string.probe_tls
        ProbeKind.UDP -> R.string.probe_udp
        ProbeKind.CAPTIVE -> R.string.probe_captive
        ProbeKind.BULK -> R.string.probe_bulk
    }

    private fun target(t: ProbeTarget): Int = when (t) {
        ProbeTarget.DOMESTIC -> R.string.probe_domestic
        ProbeTarget.FOREIGN -> R.string.probe_foreign
        ProbeTarget.FOREIGN_ALT -> R.string.probe_foreign_alt
    }

    private fun outcome(o: ProbeOutcome): Int = when (o) {
        ProbeOutcome.SUCCESS -> R.string.outcome_success
        ProbeOutcome.TIMEOUT -> R.string.outcome_timeout
        ProbeOutcome.RESET -> R.string.outcome_reset
        ProbeOutcome.REFUSED -> R.string.outcome_refused
        ProbeOutcome.DNS_TAMPERED -> R.string.outcome_dns_tampered
        ProbeOutcome.STALLED -> R.string.outcome_stalled
        ProbeOutcome.REDIRECTED -> R.string.outcome_redirected
        ProbeOutcome.UNREACHABLE -> R.string.outcome_unreachable
        ProbeOutcome.SKIPPED -> R.string.outcome_skipped
        ProbeOutcome.INCONCLUSIVE -> R.string.outcome_inconclusive
    }

    private fun restriction(c: RestrictionClass): Int = when (c) {
        RestrictionClass.UNKNOWN -> R.string.netclass_unknown
        RestrictionClass.NORMAL -> R.string.netclass_normal
        RestrictionClass.DEGRADED -> R.string.netclass_degraded
        RestrictionClass.ALLOWLIST_LIKE -> R.string.netclass_allowlist
        RestrictionClass.CAPTIVE -> R.string.netclass_captive
        RestrictionClass.OFFLINE -> R.string.netclass_offline
    }

    private fun type(t: NetworkType): Int = when (t) {
        NetworkType.WIFI -> R.string.nettype_wifi
        NetworkType.MOBILE -> R.string.nettype_mobile
        NetworkType.ETHERNET -> R.string.nettype_ethernet
        NetworkType.OTHER -> R.string.nettype_other
        NetworkType.NONE -> R.string.nettype_none
    }

    private fun confidence(c: Confidence): Int = when (c) {
        Confidence.LOW -> R.string.netconf_low
        Confidence.MEDIUM -> R.string.netconf_medium
        Confidence.HIGH -> R.string.netconf_high
    }
}
