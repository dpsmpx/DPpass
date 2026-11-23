package com.dpsmpx.dppass.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.view.View
import android.widget.Button
import android.widget.ProgressBar
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.NetworkCheck
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.Zapret2Backend
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleAttempt
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleReport
import com.dpsmpx.dppass.engine.xray.Zapret2DNSComparisonReport
import com.dpsmpx.dppass.engine.xray.Zapret2MatrixReport
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * Two opt-in Google/YouTube diagnostics. The 96-request suite must never
 * auto-run when the shorter 16-request DNS-only comparison is available;
 * without changing the VPN profile or opening a browser.
 *
 * The user can leave to cancel between attempts; a cancelled/partial test
 * is never silently copied as a completed report. The native calls have
 * bounded timeouts but cannot be interrupted inside JNI.
 */
class Zapret2AutoTestScreen(host: Host) : SubScreen(host, R.string.zapret2_autotest_title) {
    private val runButton: Button = Ui.button(
        context, R.string.zapret2_autotest_full_button, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val dnsButton: Button = Ui.button(
        context, R.string.zapret2_dns_compare_button, Ui.Style.PRIMARY, R.drawable.ic_dns)
    private val matrixButton: Button = Ui.button(
        context, R.string.zapret2_matrix_button, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val progress = ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal).apply {
        max = TOTAL
        visibility = View.GONE
    }
    private val statusText = Ui.text(context, R.style.Text_DPpass_Secondary)
    private val resultText = Ui.text(context, R.style.Text_DPpass_Body).apply {
        setTextIsSelectable(true)
        visibility = View.GONE
    }
    private var job: Job? = null
    private var started = false

    override fun content(): View = Ui.column(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Secondary,
            context.getString(R.string.zapret2_autotest_note)), Ui.matchWidth())
        addView(runButton.apply { setOnClickListener { start() } }, Ui.matchWidth())
        addView(dnsButton.apply { setOnClickListener { start(dnsComparison = true) } }, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_dns_compare_note)), Ui.matchWidth())
        addView(matrixButton.apply { setOnClickListener { startMatrix() } }, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_matrix_note)), Ui.matchWidth())
        addView(progress, Ui.matchWidth())
        addView(statusText, Ui.matchWidth())
        addView(resultText, Ui.matchWidth())
    }

    override fun onShown() {
        if (!started) {
            started = true
            statusText.text = context.getString(R.string.zapret2_autotest_choose)
            render(TunnelState.status.value)
        }
    }

    override fun render(status: TunnelStatus) {
        if (job?.isActive == true) return
        runButton.isEnabled = ready(status)
        dnsButton.isEnabled = ready(status)
        matrixButton.isEnabled = ready(status)
        if (!ready(status)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
        }
    }

    override fun onHidden() {
        job?.cancel()
        job = null
    }

    private fun ready(status: TunnelStatus): Boolean =
        host.prefs.zapret2Backend == Zapret2Backend.VPN_SERVICE &&
            status is TunnelStatus.Connected && status.profileId == ServerlessPlan.PROFILE_ID

    private fun start(dnsComparison: Boolean = false) {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        val quic = host.prefs.zapret2VpnForceTcp
        val targets = if (dnsComparison) Zapret2ProbeCatalog.dnsTargets else Zapret2ProbeCatalog.targets
        val strategies = if (dnsComparison) Zapret2ProbeCatalog.dnsStrategies else Zapret2ProbeCatalog.strategies
        val timeout = if (dnsComparison) DNS_TIMEOUT_MILLIS else TIMEOUT_MILLIS
        val total = targets.size * strategies.size * REPEATS
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        val rows = mutableListOf<Zapret2GoogleAttempt>()
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        progress.max = total
        progress.progress = 0
        progress.visibility = View.VISIBLE
        resultText.visibility = View.GONE
        statusText.text = context.getString(R.string.zapret2_autotest_progress,
            0, total, targets.first(), strategies.first(), 0, REPEATS)
        job = host.scope.launch {
            try {
                val stageStart = withContext(Dispatchers.IO) {
                    try { JniXrayRuntime.snapshotZapret2Stages() }
                    catch (_: LinkageError) { null }
                }
                var done = 0
                for (target in targets) {
                    for (strategy in strategies) {
                        for (attempt in 1..REPEATS) {
                            ensureActive()
                            // Real TLS/HTTP content checks run in the worker.
                            // No browser, manual strategy switch, or VPN restart.
                            statusText.text = context.getString(
                                R.string.zapret2_autotest_progress,
                                done, total, target, strategy, attempt, REPEATS)
                            val response = try {
                                withContext(Dispatchers.IO) {
                                    JniXrayRuntime.probeZapret2Google(strategy, target, timeout)
                                }
                            } catch (_: LinkageError) {
                                Zapret2GoogleProbe.unavailable()
                            }
                            ensureActive()
                            rows += Zapret2GoogleAttempt(strategy, attempt, response, target)
                            done++
                            progress.progress = done
                            statusText.text = context.getString(
                                R.string.zapret2_autotest_progress,
                                done, total, target, strategy, attempt, REPEATS)
                        }
                    }
                }
                val stageEnd = withContext(Dispatchers.IO) {
                    try { JniXrayRuntime.snapshotZapret2Stages() }
                    catch (_: LinkageError) { null }
                }
                val stages = if (stageStart == null || stageEnd == null) null
                    else stageEnd.delta(stageStart)
                val report = if (dnsComparison)
                    Zapret2DNSComparisonReport.render(stamp, network, rows)
                else Zapret2GoogleReport.render(stamp, network, quic, rows, stages)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    if (clipboard == null) false else {
                        clipboard.setPrimaryClip(ClipData.newPlainText(
                            if (dnsComparison) "DPpass protected DoH comparison" else "DPpass Zapret2 HTTPS diagnostics",
                            report))
                        true
                    }
                } catch (_: SecurityException) {
                    false
                } catch (_: IllegalStateException) {
                    false
                }
                statusText.text = context.getString(
                    if (copied) R.string.zapret2_autotest_done else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Google autotest cancelled")
            } finally {
                job = null
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    /** All addresses, two TCP application protocols, and a separate QUIC handshake.
     * Duplicate short DNS fingerprints are tested once to avoid repeating the
     * same IPv4 positions. The test remains opt-in and has no AUTO feedback.
     */
    private fun startMatrix() {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.max = Zapret2ProbeCatalog.matrixProviders.size
        progress.progress = 0
        resultText.visibility = View.GONE
        job = host.scope.launch {
            val rows = mutableListOf<Zapret2GoogleAttempt>()
            try {
                // Fresh certificate-verified DNS snapshots are mandatory for
                // each run; no stale Android/OS resolver cache is consulted.
                for ((index, provider) in Zapret2ProbeCatalog.matrixProviders.withIndex()) {
                    ensureActive()
                    val id = "youtube_api_matrix_" + provider + "_prepare"
                    statusText.text = context.getString(R.string.zapret2_autotest_progress,
                        index, progress.max, id, "plain", 1, 1)
                    val response = try {
                        withContext(Dispatchers.IO) {
                            JniXrayRuntime.probeZapret2Google("plain", id, DNS_TIMEOUT_MILLIS)
                        }
                    } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                    ensureActive()
                    rows += Zapret2GoogleAttempt("plain", 1, response, id)
                    progress.progress = index + 1
                }
                val seenSets = mutableSetOf<String>()
                val trials = mutableListOf<Pair<String, String>>()
                for (provider in Zapret2ProbeCatalog.matrixProviders) {
                    val id = "youtube_api_matrix_" + provider + "_prepare"
                    val answer = rows.first { it.target == id }.result
                    if (answer.outcome != "dns_ready" || answer.dnsAnswers == 0) continue
                    val key = answer.dnsFingerprint + "/" + answer.dnsAnswers
                    if (!seenSets.add(key)) continue
                    for (index in 0 until answer.dnsAnswers.coerceAtMost(16)) {
                        val prefix = "youtube_api_matrix_" + provider + "_ip" +
                            index.toString().padStart(2, '0') + "_"
                        for (protocol in listOf("h1", "h2")) {
                            for (strategy in Zapret2ProbeCatalog.matrixStrategies) {
                                trials += (prefix + protocol) to strategy
                            }
                        }
                        // QUIC bypasses the TCP desync strategy family.
                        trials += (prefix + "quic") to "plain"
                    }
                }
                val total = Zapret2ProbeCatalog.matrixProviders.size + trials.size
                progress.max = total
                for ((index, trial) in trials.withIndex()) {
                    ensureActive()
                    val done = Zapret2ProbeCatalog.matrixProviders.size + index
                    statusText.text = context.getString(R.string.zapret2_autotest_progress,
                        done, total, trial.first, trial.second, 1, 1)
                    val response = try {
                        withContext(Dispatchers.IO) {
                            JniXrayRuntime.probeZapret2Google(trial.second, trial.first, MATRIX_TIMEOUT_MILLIS)
                        }
                    } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                    ensureActive()
                    rows += Zapret2GoogleAttempt(trial.second, 1, response, trial.first)
                    progress.progress = done + 1
                }
                val report = Zapret2MatrixReport.render(stamp, network, rows)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    context.getSystemService(ClipboardManager::class.java)?.let {
                        it.setPrimaryClip(ClipData.newPlainText("DPpass IPv4 TLS HTTP2 QUIC", report))
                        true
                    } ?: false
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(
                    if (copied) R.string.zapret2_autotest_done else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("IP matrix cancelled")
            } finally {
                job = null
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    private companion object {
        const val REPEATS = 2
        const val TIMEOUT_MILLIS = 8_000
        const val DNS_TIMEOUT_MILLIS = 12_000
        const val MATRIX_TIMEOUT_MILLIS = 5_000
        val TOTAL: Int = Zapret2ProbeCatalog.targets.size *
            Zapret2ProbeCatalog.strategies.size * REPEATS
    }
}
