package com.dpsmpx.dppass.app.ui

import android.text.InputType
import android.view.View
import android.widget.Button
import android.widget.EditText
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.NetworkCheck
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.TrialReport
import com.dpsmpx.dppass.connection.TrialSettings
import com.dpsmpx.dppass.connection.TrialSummary
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Замер А/Б» эксперимента с началом соединения (D-116,
 * `docs/research/FAKE_PACKETS.md`, §6.2): только к своему выбранному
 * серверу, только при выключенном VPN. Варианты — без приёма, разбиение
 * (D-68), перестановка, подделка с каждым TTL из диапазона — вперемешку, по
 * N попыток, с паузой. Итог — успехи, медиана времени, виды отказов и сколько
 * раз приёма не было; он же — в журнале (без адресов). Это наблюдение для
 * одной сети на дату, а не обещание (D-13).
 */
class DesyncTrialScreen(host: Host) : SubScreen(host, R.string.desync_title) {
    private val ttlFrom: EditText = Ui.field(context, R.string.desync_ttl_from, InputType.TYPE_CLASS_NUMBER).apply { setText(DEFAULTS.ttlFrom.toString()) }
    private val ttlTo: EditText = Ui.field(context, R.string.desync_ttl_to, InputType.TYPE_CLASS_NUMBER).apply { setText(DEFAULTS.ttlTo.toString()) }
    private val attempts: EditText = Ui.field(context, R.string.desync_attempts, InputType.TYPE_CLASS_NUMBER).apply { setText(DEFAULTS.attempts.toString()) }
    private val run: Button = Ui.button(context, R.string.desync_run, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val hint = Ui.text(context, R.style.Text_DPpass_Caption)
    private val progress = Ui.text(context, R.style.Text_DPpass_Secondary).apply { visibility = View.GONE }
    private val results = Ui.listCard(context).apply { visibility = View.GONE }
    private var job: Job? = null

    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.desync_intro)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.desync_warning)).apply {
                setTextColor(context.getColor(R.color.warning))
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(ttlFrom, Ui.matchWidth())
        addView(ttlTo, Ui.matchWidth())
        addView(attempts, Ui.matchWidth())
        addView(run.apply { setOnClickListener { start() } }, Ui.matchWidth())
        addView(hint)
        addView(progress)
        addView(results, Ui.matchWidth())
    }

    override fun render(status: TunnelStatus) {
        if (job?.isActive == true) return
        // Попытки — ядром без TUN: ядро одно на процесс, при поднятом VPN замер невозможен.
        val off = status is TunnelStatus.Idle || (status is TunnelStatus.Failed && !status.trafficBlocked)
        val server = serverName()
        run.isEnabled = off && server != null
        hint.text = when {
            server == null -> context.getString(R.string.desync_no_server)
            !off -> context.getString(R.string.desync_needs_vpn_off)
            else -> context.getString(R.string.desync_server, Avatar.stripFlag(server))
        }
    }

    override fun onHidden() {
        // Ушли с экрана — замер останавливается: его никто не ждёт.
        job?.cancel()
        job = null
    }

    private fun serverName(): String? {
        val ir = host.graph?.core?.activation?.state?.activeConfig ?: return null
        val id = host.prefs.selectedServer ?: return ir.profiles.firstOrNull()?.name
        return ir.profiles.firstOrNull { it.id == id }?.name
    }

    private fun start() {
        val graph = host.graph ?: return
        val core = graph.core
        if (job?.isActive == true) return
        val ir = core.activation.state.activeConfig ?: return
        val profile = host.prefs.selectedServer?.let { id -> ir.profiles.firstOrNull { it.id == id } } ?: ir.profiles.firstOrNull() ?: return
        val settings = TrialSettings(
            ttlFrom = ttlFrom.text.toString().toIntOrNull() ?: -1,
            ttlTo = ttlTo.text.toString().toIntOrNull() ?: -1,
            attempts = attempts.text.toString().toIntOrNull() ?: -1,
            pauseMillis = DEFAULTS.pauseMillis,
        )
        settings.problem()?.let {
            host.toast(it)
            return
        }
        val timeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, _ -> withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, timeout) } }
        // Тип сети и режим (D-64) — в журнал замера: итог — наблюдение для этой сети.
        val net = NetworkCheck.underlying(context)
        val regime = NetworkCheck.regime(context)?.restriction ?: RestrictionClass.UNKNOWN
        run.isEnabled = false
        results.visibility = View.GONE
        progress.visibility = View.VISIBLE
        progress.text = context.getString(R.string.desync_progress, 0, settings.variants().size * settings.attempts)
        job = host.scope.launch {
            try {
                val r = core.desyncTrial().run(
                    ir,
                    profile.id,
                    checker,
                    settings,
                    listOf("network" to net.type, "regime" to regime, "ttl_from" to settings.ttlFrom, "ttl_to" to settings.ttlTo),
                    pause = { delay(it) },
                ) { done, total -> context.runOnUiThread { progress.text = context.getString(R.string.desync_progress, done, total) } }
                when (r) {
                    is Outcome.Success -> show(r.value)
                    is Outcome.Failure -> host.problem(context.getString(R.string.desync_failed), r.errors.first())
                }
            } finally {
                core.log.info("desync_trial_finished", "by" to Safe(if (job?.isCancelled == true) "left" else "done"))
                job = null
                render(TunnelState.status.value)
            }
        }
    }

    private fun show(report: TrialReport) {
        progress.visibility = View.GONE
        results.removeAllViews()
        for ((i, s) in report.summaries.withIndex()) {
            if (i > 0) results.addView(Ui.divider(context))
            results.addView(Ui.ListRow(context, if (s.ok > 0) R.drawable.ic_check else R.drawable.ic_block, title(s)).subtitle(line(s)), Ui.matchWidth())
        }
        results.visibility = View.VISIBLE
    }

    private fun title(s: TrialSummary): String = when {
        s.variant == "plain" -> context.getString(R.string.desync_variant_plain)
        s.variant == "split" -> context.getString(R.string.desync_variant_split)
        s.variant == "disorder" -> context.getString(R.string.desync_variant_disorder)
        else -> context.getString(R.string.desync_variant_fake, s.variant.removePrefix("fake-"))
    }

    private fun line(s: TrialSummary): String {
        val parts = mutableListOf(context.getString(R.string.desync_ok, s.ok, s.total))
        s.medianMillis?.let { parts += context.getString(R.string.desync_median, it) }
        if (s.failures.isNotEmpty()) parts += s.failures.entries.joinToString(", ") { "${it.key.name}×${it.value}" }
        if (s.notApplied > 0) parts += context.getString(R.string.desync_not_applied, s.notApplied)
        return parts.joinToString(" · ")
    }

    private companion object {
        val DEFAULTS = TrialSettings()
        const val PROBE_MARGIN_MILLIS = 2_000L
    }
}
