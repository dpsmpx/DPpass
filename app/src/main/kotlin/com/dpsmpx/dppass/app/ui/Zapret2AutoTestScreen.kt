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
 * One-tap, in-app Google HTTPS strategy matrix. On first display, tests
 * every VpnService TCP candidate twice through the existing Xray engine,
 * without changing the VPN profile or opening a browser.
 *
 * The user can leave to cancel between attempts; a cancelled/partial test
 * is never silently copied as a completed report. The native calls have
 * bounded timeouts but cannot be interrupted inside JNI.
 */
class Zapret2AutoTestScreen(host: Host) : SubScreen(host, R.string.zapret2_autotest_title) {
    private val runButton: Button = Ui.button(
        context, R.string.zapret2_autotest_again, Ui.Style.PRIMARY, R.drawable.ic_speed)
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
        addView(progress, Ui.matchWidth())
        addView(statusText, Ui.matchWidth())
        addView(resultText, Ui.matchWidth())
    }

    override fun onShown() {
        if (!started) {
            started = true
            start()
        }
    }

    override fun render(status: TunnelStatus) {
        if (job?.isActive == true) return
        runButton.isEnabled = ready(status)
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

    private fun start() {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        val quic = host.prefs.zapret2VpnForceTcp
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        val rows = mutableListOf<Zapret2GoogleAttempt>()
        runButton.isEnabled = false
        progress.progress = 0
        progress.visibility = View.VISIBLE
        resultText.visibility = View.GONE
        statusText.text = context.getString(R.string.zapret2_autotest_progress, 0, TOTAL, "plain", 0, REPEATS)
        job = host.scope.launch {
            try {
                var done = 0
                for (strategy in Zapret2ProbeCatalog.strategies) {
                    for (attempt in 1..REPEATS) {
                        ensureActive()
                        // The UX remains responsive while the native, cert-
                        // verified HTTP probe is running on a worker thread.
                        statusText.text = context.getString(
                            R.string.zapret2_autotest_progress, done, TOTAL, strategy, attempt, REPEATS)
                        val response = try {
                            withContext(Dispatchers.IO) {
                                JniXrayRuntime.probeZapret2Google(strategy, TIMEOUT_MILLIS)
                            }
                        } catch (e: LinkageError) {
                            Zapret2GoogleProbe.unavailable()
                        }
                        ensureActive()
                        rows += Zapret2GoogleAttempt(strategy, attempt, response)
                        done++
                        progress.progress = done
                        statusText.text = context.getString(
                            R.string.zapret2_autotest_progress, done, TOTAL, strategy, attempt, REPEATS)
                    }
                }
                val report = Zapret2GoogleReport.render(stamp, network, quic, rows)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    if (clipboard == null) false else {
                        clipboard.setPrimaryClip(ClipData.newPlainText("DPpass Zapret2 Google autotest", report))
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
            }
        }
    }

    private companion object {
        const val REPEATS = 2
        const val TIMEOUT_MILLIS = 8_000
        val TOTAL: Int = Zapret2ProbeCatalog.strategies.size * REPEATS
    }
}
