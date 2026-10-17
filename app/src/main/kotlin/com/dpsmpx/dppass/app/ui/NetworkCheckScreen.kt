package com.dpsmpx.dppass.app.ui

import android.view.View
import android.widget.Button
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.NetworkCheck
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.network.Confidence
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeKind
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.ProbeTarget
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch

/**
 * «Проверка сети» (D-60): по кнопке — пробы D-14 мимо туннеля, исход
 * каждой и класс сети с доводами. Итог только для сведения: в план
 * подключения он пока не идёт.
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

    override fun content(): View = Ui.column(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.netcheck_intro)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
        addView(run.apply { setOnClickListener { start() } }, Ui.matchWidth())
        addView(verdict, Ui.matchWidth())
        addView(probes, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.netcheck_note)).apply { setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0) })
    }

    override fun render(status: TunnelStatus) = Unit

    override fun onHidden() {
        // Ушли с экрана — проверка останавливается: её никто не ждёт.
        job?.cancel()
        job = null
        run.isEnabled = true
        run.setText(R.string.netcheck_run)
    }

    private fun start() {
        val core = host.graph?.core ?: return
        if (job?.isActive == true) return
        run.isEnabled = false
        run.setText(R.string.netcheck_running)
        verdict.visibility = View.GONE
        probes.removeAllViews()
        probes.visibility = View.VISIBLE
        job = host.scope.launch {
            try {
                val result = NetworkCheck.run(context, core.log) { r -> context.runOnUiThread { addProbe(r) } }
                showVerdict(result)
            } finally {
                run.isEnabled = true
                run.setText(R.string.netcheck_run)
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
        ) + a.evidence.map { "• $it" }
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
