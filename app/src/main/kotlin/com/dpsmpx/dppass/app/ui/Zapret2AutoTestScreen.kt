package com.dpsmpx.dppass.app.ui

import android.content.ClipData
import android.content.ClipboardManager
import android.os.SystemClock
import android.view.View
import android.text.InputType
import android.widget.EditText
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
import com.dpsmpx.dppass.engine.xray.Zapret2H3Policy
import com.dpsmpx.dppass.engine.xray.Zapret2H3Report
import com.dpsmpx.dppass.engine.xray.Zapret2SiteSearch
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
    private val h3Button: Button = Ui.button(
        context, R.string.zapret2_h3_button, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val siteInput = EditText(context).apply {
        hint = context.getString(R.string.zapret2_site_search_host_hint)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        isSingleLine = true
        maxLines = 1
        contentDescription = context.getString(R.string.zapret2_site_search_host_hint)
    }
    private val siteButton: Button = Ui.button(
        context, R.string.zapret2_site_search_button, Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val siteQuicButton: Button = Ui.button(
        context, R.string.zapret2_site_quic_button, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val youtubeHomeButton: Button = Ui.button(
        context, R.string.zapret2_youtube_home_button, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val youtubeApiButton: Button = Ui.button(
        context, R.string.zapret2_youtube_api_button, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val youtubeThumbnailButton: Button = Ui.button(
        context, R.string.zapret2_youtube_thumbnail_button, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val youtubeApiSweepButton: Button = Ui.button(
        context, R.string.zapret2_youtube_api_sweep_button, Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val apiSniControlButton: Button = Ui.button(
        context, R.string.zapret2_youtube_api_sni_control_button, Ui.Style.OUTLINE, R.drawable.ic_dns)
    private val apiTLSVersionButton: Button = Ui.button(
        context, R.string.zapret2_youtube_api_tls_version_button, Ui.Style.OUTLINE, R.drawable.ic_dns)
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
        addView(h3Button.apply { setOnClickListener { startH3() } }, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_h3_note)), Ui.matchWidth())
        addView(Ui.section(context, context.getString(R.string.zapret2_site_search_button)),
            Ui.matchWidth())
        addView(siteInput, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_youtube_hosts_note)), Ui.matchWidth())
        addView(youtubeHomeButton.apply { setOnClickListener {
            siteInput.setText("www.youtube.com")
            startSiteSearch(quic = false)
        } }, Ui.matchWidth())
        addView(youtubeApiButton.apply { setOnClickListener {
            siteInput.setText("youtubei.googleapis.com")
            startSiteSearch(quic = false)
        } }, Ui.matchWidth())
        addView(youtubeThumbnailButton.apply { setOnClickListener {
            siteInput.setText("i.ytimg.com")
            startSiteSearch(quic = false)
        } }, Ui.matchWidth())
        addView(youtubeApiSweepButton.apply { setOnClickListener {
            startYoutubeApiSweep()
        } }, Ui.matchWidth())
        addView(apiSniControlButton.apply { setOnClickListener {
            startSameIpSniControl()
        } }, Ui.matchWidth())
        addView(apiTLSVersionButton.apply { setOnClickListener {
            startTLSVersionControl()
        } }, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_youtube_api_tls_version_note)), Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_youtube_api_sni_control_note)), Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_youtube_api_sweep_note)), Ui.matchWidth())
        addView(siteButton.apply { setOnClickListener { startSiteSearch(quic = false) } },
            Ui.matchWidth())
        addView(siteQuicButton.apply { setOnClickListener { startSiteSearch(quic = true) } },
            Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.zapret2_site_search_note)), Ui.matchWidth())
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
        h3Button.isEnabled = ready(status)
        siteButton.isEnabled = ready(status)
        siteQuicButton.isEnabled = ready(status)
        youtubeHomeButton.isEnabled = ready(status)
        youtubeApiButton.isEnabled = ready(status)
        youtubeThumbnailButton.isEnabled = ready(status)
        youtubeApiSweepButton.isEnabled = ready(status)
        apiSniControlButton.isEnabled = ready(status)
        apiTLSVersionButton.isEnabled = ready(status)
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
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
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
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
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
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.max = Zapret2ProbeCatalog.matrixProviders.size
        progress.progress = 0
        resultText.visibility = View.GONE
        job = host.scope.launch {
            val rows = mutableListOf<Zapret2GoogleAttempt>()
            try {
                // Google control is prepared first, before the long YouTube
                // matrix. All A answers use fixed, verified DoH rather than
                // the configured Android DNS.
                val preparations = listOf("google_control_prepare") +
                    Zapret2ProbeCatalog.matrixProviders.map { "youtube_api_matrix_" + it + "_prepare" }
                progress.max = preparations.size
                for ((index, id) in preparations.withIndex()) {
                    ensureActive()
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
                val control = rows.first { it.target == "google_control_prepare" }.result
                if (control.outcome == "dns_ready") {
                    // Two Google A addresses, one baseline mode, three
                    // protocols each: six short fixed controls maximum.
                    for (index in 0 until control.dnsAnswers.coerceAtMost(2)) {
                        val prefix = "google_control_ip" + index.toString().padStart(2, '0') + "_"
                        for (protocol in listOf("h1", "h2", "quic")) {
                            trials += (prefix + protocol) to "plain"
                        }
                    }
                }
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
                val total = preparations.size + trials.size
                progress.max = total
                for ((index, trial) in trials.withIndex()) {
                    ensureActive()
                    val done = preparations.size + index
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
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }


    /**
     * Opt-in, short-lived target-specific HTTP/3 experiment. First check
     * all fixed Google-DoH YouTube IPv4 addresses once; retry successes
     * twice (three independent QUIC connections total). Only stable
     * candidates receive an actual H3 GET and anonymous YouTube browse
     * POST. Failing candidates are skipped automatically within this run;
     * the normal VPN, system DNS and AUTO are never modified.
     */
    private fun startH3() {
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
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        progress.max = 1
        progress.progress = 0
        progress.visibility = View.VISIBLE
        resultText.visibility = View.GONE
        job = host.scope.launch {
            val rows = mutableListOf<Zapret2GoogleAttempt>()
            var done = 0
            var expired = false
            try {
                suspend fun attempt(target: String, number: Int, maxAttempts: Int,
                    timeout: Int): Zapret2GoogleAttempt {
                    ensureActive()
                    if (!ready(TunnelState.status.value)) {
                        throw CancellationException("VpnService disconnected during H3 diagnostic")
                    }
                    statusText.text = context.getString(R.string.zapret2_autotest_progress,
                        done, progress.max, target, "plain", number, maxAttempts)
                    val result = try {
                        withContext(Dispatchers.IO) {
                            JniXrayRuntime.probeZapret2Google("plain", target, timeout)
                        }
                    } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                    ensureActive()
                    val row = Zapret2GoogleAttempt("plain", number, result, target)
                    rows += row
                    done++
                    progress.progress = done
                    return row
                }

                // Same-run Google QUIC control: the exact same protected Xray
                // UDP adapter is sampled before and after YouTube. Do not
                // interpret a YouTube timeout as selective filtering when this
                // control also fails. No live routes or AUTO are modified.
                progress.max = done + 1
                val googlePreparation = attempt("google_control_prepare", 1, 1,
                    DNS_TIMEOUT_MILLIS).result
                val googleReady = googlePreparation.outcome == "dns_ready" &&
                    googlePreparation.dnsAnswers > 0
                if (googleReady) {
                    progress.max = done + 1
                    attempt("google_control_ip00_quic", 1, 2, MATRIX_TIMEOUT_MILLIS)
                }

                progress.max = done + 1
                val preparation = attempt("youtube_api_h3_prepare", 1, 1,
                    DNS_TIMEOUT_MILLIS).result
                if (preparation.outcome == "dns_ready" && preparation.dnsAnswers > 0) {
                    val preparedAt = SystemClock.elapsedRealtime()
                    val count = preparation.dnsAnswers.coerceAtMost(16)
                    val viable = mutableListOf<Int>()
                    progress.max = done + count
                    for (index in 0 until count) {
                        if (!Zapret2H3Policy.fresh(preparedAt,
                                SystemClock.elapsedRealtime())) {
                            expired = true
                            break
                        }
                        val row = attempt(Zapret2H3Policy.target(index, "quic"),
                            1, 3, MATRIX_TIMEOUT_MILLIS)
                        if (row.result.outcome == "quic_verified" &&
                            row.result.tlsStage == "quic_tls_verified" &&
                            row.result.alpn == "h3") viable += index
                    }

                    // A single returned datagram may be a Version Negotiation,
                    // Retry, truncated packet or unrelated/invalid UDP response.
                    // Recheck at most two failed-first-attempt addresses once,
                    // strictly as evidence. These cannot qualify for H3.
                    val peerReplyRechecks = Zapret2H3Policy.peerReplyRechecks(rows)
                    progress.max = done + peerReplyRechecks.size
                    for (index in peerReplyRechecks) {
                        if (!Zapret2H3Policy.fresh(preparedAt,
                                SystemClock.elapsedRealtime())) {
                            expired = true
                            break
                        }
                        attempt(Zapret2H3Policy.target(index, "quic"),
                            2, 2, MATRIX_TIMEOUT_MILLIS)
                    }

                    // Complete all three independent samples for every
                    // first-pass verified IP, even if the second one fails.
                    // This measures intermittent 1/3 and 2/3 reachability
                    // without relaxing the strict 3/3 HTTP/3 admission rule.
                    val stable = mutableListOf<Int>()
                    progress.max = done + viable.size * 2
                    for (index in viable) {
                        if (!Zapret2H3Policy.fresh(preparedAt,
                                SystemClock.elapsedRealtime())) {
                            expired = true
                            break
                        }
                        val quicRows = rows.filter {
                            it.target == Zapret2H3Policy.target(index, "quic")
                        }.toMutableList()
                        for (number in 2..3) {
                            val row = attempt(Zapret2H3Policy.target(index, "quic"),
                                number, 3, MATRIX_TIMEOUT_MILLIS)
                            quicRows += row
                            // Keep the third attempt even after a timeout:
                            // a later recovered handshake is diagnostic evidence.
                            // stable(quicRows) still requires all 3 verified.
                        }
                        if (Zapret2H3Policy.stable(quicRows)) stable += index
                    }

                    // QUIC v2 is an optional diagnostic comparison, never
                    // a replacement for the 3/3 QUIC v1 HTTP/3 admission rule.
                    // If the Google v2 baseline cannot verify TLS+ALPN, probing
                    // all YouTube IPs under v2 would produce uninterpretable
                    // negative results (including legitimate Version Negotiation).
                    if (stable.isEmpty() && !expired && googleReady) {
                        progress.max = done + 1
                        val v2Before = attempt("google_control_ip00_quicv2", 1, 2,
                            MATRIX_TIMEOUT_MILLIS)
                        if (Zapret2H3Policy.verifiedV2Control(v2Before)) {
                            progress.max = done + count
                            for (index in 0 until count) {
                                if (!Zapret2H3Policy.fresh(preparedAt,
                                        SystemClock.elapsedRealtime())) {
                                    expired = true
                                    break
                                }
                                attempt(Zapret2H3Policy.target(index, "quicv2"),
                                    1, 1, MATRIX_TIMEOUT_MILLIS)
                            }
                        }
                        // Repeat the independent control regardless of the
                        // first outcome, provided the RRset has not expired.
                        if (Zapret2H3Policy.fresh(preparedAt,
                                SystemClock.elapsedRealtime())) {
                            progress.max = done + 1
                            attempt("google_control_ip00_quicv2", 2, 2,
                                MATRIX_TIMEOUT_MILLIS)
                        } else {
                            expired = true
                        }
                    }

                    progress.max = done + stable.size * 2
                    for (index in stable) {
                        if (!Zapret2H3Policy.fresh(preparedAt,
                                SystemClock.elapsedRealtime())) {
                            expired = true
                            break
                        }
                        val get = attempt(Zapret2H3Policy.target(index, "h3"),
                            1, 1, H3_TIMEOUT_MILLIS)
                        // If HTTP/3 GET fails, this address is discarded in
                        // favour of the next independently stable candidate.
                        if (!get.result.httpReachable) continue
                        val api = attempt(Zapret2H3Policy.target(index, "h3api"),
                            1, 1, H3_TIMEOUT_MILLIS)
                        if (api.result.outcome == "h3_api_json_valid") break
                    }
                }
                // The post-control is independent of all YouTube candidates.
                // A passed pre-control alone cannot prove UDP stayed healthy
                // during the YouTube scan.
                if (googleReady) {
                    progress.max = done + 1
                    attempt("google_control_ip00_quic", 2, 2, MATRIX_TIMEOUT_MILLIS)
                }
                val report = Zapret2H3Report.render(stamp, network, rows) +
                    if (expired) "Experiment expired after five minutes; rerun for fresh DoH addresses.\n" else ""
                resultText.text = report
                resultText.visibility = View.VISIBLE
                progress.max = done.coerceAtLeast(1)
                progress.progress = done
                val copied = try {
                    context.getSystemService(ClipboardManager::class.java)?.let {
                        it.setPrimaryClip(ClipData.newPlainText("DPpass protected HTTP3 YouTube API", report))
                        true
                    } ?: false
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(
                    if (copied) R.string.zapret2_autotest_done else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("YouTube H3 diagnostic cancelled")
            } finally {
                job = null
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    /**
     * Complete bounded strategy search for any explicitly entered *public*
     * hostname. All probes use native protected DoH+Xray; no direct Android
     * DNS, browser, arbitrary URL/path, custom packet injector or user data.
     * TCP may seed the existing per-host AUTO selector only with fully
     * independent, verified 3/3 results on every selected address. QUIC is
     * diagnostic only because routing by shared IPv4 cannot be attributed
     * safely to the user's specific hostname.
     */
    private fun startSiteSearch(quic: Boolean) {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val domain = Zapret2SiteSearch.normalizedHost(siteInput.text.toString())
        if (domain == null) {
            statusText.text = context.getString(R.string.zapret2_site_search_invalid)
            host.toast(statusText.text)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        val methods = if (quic) Zapret2SiteSearch.quicMethods else Zapret2SiteSearch.tcpMethods
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        siteInput.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.progress = 0
        progress.max = methods.size * Zapret2SiteSearch.MAX_IPS * Zapret2SiteSearch.ATTEMPTS
        resultText.visibility = View.GONE
        statusText.text = "DoH · $domain"
        job = host.scope.launch {
            try {
                val prepared = try {
                    withContext(Dispatchers.IO) {
                        JniXrayRuntime.probeZapret2Google(
                            "plain", Zapret2SiteSearch.prepare(domain), DNS_TIMEOUT_MILLIS)
                    }
                } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val ipCount = prepared.dnsAnswers.coerceAtMost(Zapret2SiteSearch.MAX_IPS)
                val total = methods.size * ipCount * Zapret2SiteSearch.ATTEMPTS
                val preparedAt = SystemClock.elapsedRealtime()
                progress.max = total
                progress.progress = 0
                val rows = mutableListOf<Zapret2GoogleAttempt>()
                var expired = false
                // Interleave methods across repetitions so a brief
                // network change does not make all later profiles appear
                // faster than the earlier baseline. Each numbered sample
                // is still one independent protected Xray connection.
                scan@ for (number in 1..Zapret2SiteSearch.ATTEMPTS) {
                    for (ip in 0 until ipCount) {
                        for (method in methods) {
                            ensureActive()
                            if (!ready(TunnelState.status.value) ||
                                NetworkCheck.underlying(context).type.toString() != network ||
                                SystemClock.elapsedRealtime() - preparedAt >=
                                    Zapret2SiteSearch.TTL_MS - SITE_TIMEOUT_MILLIS) {
                                expired = true
                                break@scan
                            }
                            val target = Zapret2SiteSearch.trial(domain, ip, number, quic)
                            statusText.text = context.getString(
                                R.string.zapret2_autotest_progress,
                                rows.size, total, domain + " IPv4 #$ip", method,
                                number, Zapret2SiteSearch.ATTEMPTS)
                            val response = try {
                                withContext(Dispatchers.IO) {
                                    JniXrayRuntime.probeZapret2Google(
                                        method, target, SITE_TIMEOUT_MILLIS)
                                }
                            } catch (_: LinkageError) {
                                Zapret2GoogleProbe.unavailable()
                            }
                            ensureActive()
                            rows += Zapret2GoogleAttempt(method, number, response, target)
                            progress.progress = rows.size
                            if (response.outcome == "dns_not_prepared" ||
                                response.outcome == "engine_off") {
                                expired = true
                                break@scan
                            }
                        }
                    }
                }
                if (expired || rows.size != total) {
                    statusText.text = context.getString(R.string.zapret2_site_search_expired)
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val selection = Zapret2SiteSearch.recommend(domain, ipCount, rows, quic)
                // Cross-module data-class getters are not eligible for a
                // Kotlin smart cast inside withContext's coroutine lambda.
                val selectedMethod = selection.method
                val commit = if (!quic && selectedMethod != null &&
                    (selection.readyToApply || selection.baselineStable)) {
                    try {
                        withContext(Dispatchers.IO) {
                            JniXrayRuntime.probeZapret2Google(
                                selectedMethod, Zapret2SiteSearch.apply(domain), 1_500)
                        }
                    } catch (_: LinkageError) {
                        Zapret2GoogleProbe.unavailable()
                    }
                } else null
                val report = Zapret2SiteSearch.report(
                    domain, network, quic, prepared, rows, selection, commit)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    val clipboard = context.getSystemService(ClipboardManager::class.java)
                    if (clipboard == null) false else {
                        clipboard.setPrimaryClip(ClipData.newPlainText(
                            "DPpass site strategy search", report))
                        true
                    }
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(if (copied)
                    R.string.zapret2_autotest_done
                    else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Any-site strategy search cancelled")
            } finally {
                job = null
                siteInput.isEnabled = true
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    /**
     * Negative API-specific differential diagnosis. Unlike siteSearch(),
     * this covers up to eight authenticated DoH A records and compares
     * H1 and H2 ALPN on the exact same SNI/IP. It never invokes site_apply,
     * never stores an IP, and cannot teach AUTO from a one-off success.
     */
    private fun startYoutubeApiSweep() {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        siteInput.isEnabled = false
        resultText.visibility = View.GONE
        progress.visibility = View.VISIBLE
        progress.progress = 0
        statusText.text = "DoH · ${Zapret2SiteSearch.YOUTUBE_API_HOST}"
        job = host.scope.launch {
            try {
                val prepared = try {
                    withContext(Dispatchers.IO) {
                        JniXrayRuntime.probeZapret2Google("plain",
                            Zapret2SiteSearch.prepare(Zapret2SiteSearch.YOUTUBE_API_HOST),
                            DNS_TIMEOUT_MILLIS)
                    }
                } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val ipCount = prepared.dnsAnswers.coerceAtMost(Zapret2SiteSearch.MAX_SWEEP_IPS)
                val profiles = Zapret2SiteSearch.apiSweepProfiles
                val startedAt = SystemClock.elapsedRealtime()
                val rows = mutableListOf<Zapret2GoogleAttempt>()
                val total = ipCount * profiles.size
                progress.max = total + 4 // at most two confirmed candidates receive two repeats
                var invalid = false
                scan@ for (ip in 0 until ipCount) {
                    for ((proto, method) in profiles) {
                        ensureActive()
                        if (!ready(TunnelState.status.value) ||
                            NetworkCheck.underlying(context).type.toString() != network ||
                            SystemClock.elapsedRealtime() - startedAt >=
                                Zapret2SiteSearch.TTL_MS - API_SWEEP_TIMEOUT_MILLIS) {
                            invalid = true
                            break@scan
                        }
                        val target = Zapret2SiteSearch.apiSweepTrial(ip, 1, proto)
                        statusText.text = "API IPv4 #$ip · $proto / $method · ${rows.size}/$total"
                        val response = try {
                            withContext(Dispatchers.IO) {
                                JniXrayRuntime.probeZapret2Google(
                                    method, target, API_SWEEP_TIMEOUT_MILLIS)
                            }
                        } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                        ensureActive()
                        rows += Zapret2GoogleAttempt(method, 1, response, target)
                        progress.progress = rows.size
                        if (response.outcome == "dns_not_prepared" ||
                            response.outcome == "engine_off") {
                            invalid = true
                            break@scan
                        }
                    }
                }
                if (invalid || rows.size != total) {
                    statusText.text = context.getString(R.string.zapret2_site_search_expired)
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                // Confirm up to two transport-positive IP/protocol/method
                // tuples using independent connections. This is evidence
                // only and never passes through AUTO's commit interface.
                val candidates = rows.filter {
                    it.result.tlsStage == "tls_verified" &&
                        it.result.httpStatus in 200..499
                }.take(2).toList()
                repeatScan@ for (candidate in candidates) {
                    for (attempt in 2..Zapret2SiteSearch.ATTEMPTS) {
                        ensureActive()
                        if (!ready(TunnelState.status.value) ||
                            NetworkCheck.underlying(context).type.toString() != network ||
                            SystemClock.elapsedRealtime() - startedAt >=
                                Zapret2SiteSearch.TTL_MS - API_SWEEP_TIMEOUT_MILLIS) {
                            break@repeatScan
                        }
                        val target = Zapret2SiteSearch.apiSweepTrial(
                            candidate.result.ipIndex, attempt, candidate.result.protocol)
                        statusText.text = "API IPv4 #${candidate.result.ipIndex} · " +
                            "${candidate.result.protocol} / ${candidate.strategy} · $attempt/3"
                        val response = try {
                            withContext(Dispatchers.IO) {
                                JniXrayRuntime.probeZapret2Google(
                                    candidate.strategy, target, API_SWEEP_TIMEOUT_MILLIS)
                            }
                        } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                        ensureActive()
                        rows += Zapret2GoogleAttempt(candidate.strategy, attempt,
                            response, target)
                        progress.progress = rows.size
                        if (response.outcome == "dns_not_prepared" ||
                            response.outcome == "engine_off") break@repeatScan
                    }
                }
                progress.max = rows.size
                progress.progress = rows.size
                val report = Zapret2SiteSearch.apiSweepReport(
                    network, prepared, rows, ipCount)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    context.getSystemService(ClipboardManager::class.java)?.let {
                        it.setPrimaryClip(ClipData.newPlainText(
                            "DPpass API IP/H2 sweep", report))
                        true
                    } ?: false
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(if (copied)
                    R.string.zapret2_autotest_done
                    else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("API IPv4/H2 sweep cancelled")
            } finally {
                job = null
                siteInput.isEnabled = true
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    /**
     * Compares two certificate-verified SNI identities on exactly the SAME
     * pinned public API IP. The google.com control can legitimately fail on
     * an API IP; only an independently verified successful control is useful
     * evidence for host/SNI-specific treatment.
     *
     * This is user-initiated diagnosis only, not a domain-fronting proxy.
     */
    private fun startSameIpSniControl() {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        siteInput.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.progress = 0
        resultText.visibility = View.GONE
        statusText.text = "DoH · API и Google TLS"
        job = host.scope.launch {
            try {
                suspend fun probe(method: String, target: String, ms: Int):
                    Zapret2GoogleProbe = try {
                    withContext(Dispatchers.IO) {
                        JniXrayRuntime.probeZapret2Google(method, target, ms)
                    }
                } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                val prepared = probe("plain", Zapret2SiteSearch.prepare(
                    Zapret2SiteSearch.YOUTUBE_API_HOST), DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val preparedAt = SystemClock.elapsedRealtime()
                val ownPrepared = probe("plain", "google_control_prepare", DNS_TIMEOUT_MILLIS)
                ensureActive()
                val ownControl = if (ownPrepared.outcome == "dns_ready" &&
                    ownPrepared.dnsAnswers > 0)
                    probe("plain", "google_control_ip00_h1", SNI_CONTROL_TIMEOUT_MILLIS)
                else null
                ensureActive()
                val ipCount = prepared.dnsAnswers.coerceAtMost(
                    Zapret2SiteSearch.MAX_SWEEP_IPS)
                val rows = mutableListOf<Zapret2GoogleAttempt>()
                progress.max = ipCount * 2 + 8
                var expired = false
                suspend fun check(ip: Int, attempt: Int, google: Boolean) {
                    val target = if (google) Zapret2SiteSearch.sameIpControlTrial(ip, attempt)
                        else Zapret2SiteSearch.apiSweepTrial(ip, attempt, "h1")
                    val name = if (google) "Google SNI" else "YouTube API SNI"
                    statusText.text = "IPv4 #$ip · $name · $attempt/3"
                    val response = probe("plain", target, SNI_CONTROL_TIMEOUT_MILLIS)
                    ensureActive()
                    rows += Zapret2GoogleAttempt("plain", attempt, response, target)
                    progress.progress = rows.size
                    if (response.outcome == "dns_not_prepared" ||
                        response.outcome == "engine_off") expired = true
                }
                scan@ for (ip in 0 until ipCount) {
                    for (google in listOf(false, true)) {
                        ensureActive()
                        if (!ready(TunnelState.status.value) ||
                            NetworkCheck.underlying(context).type.toString() != network ||
                            SystemClock.elapsedRealtime() - preparedAt >=
                                Zapret2SiteSearch.TTL_MS - SNI_CONTROL_TIMEOUT_MILLIS) {
                            expired = true
                            break@scan
                        }
                        check(ip, 1, google)
                        if (expired) break@scan
                    }
                }
                if (expired || rows.size != ipCount * 2) {
                    statusText.text = context.getString(R.string.zapret2_site_search_expired)
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                // Independently repeat up to two successful same-IP Google
                // controls, each paired to the original YouTube API SNI.
                // At most 8 follow-up sockets, all diagnostic.
                val comparisonIPs = rows.filter {
                    it.target.startsWith("site_sni_google_ip") &&
                        it.result.tlsStage == "tls_verified" &&
                        it.result.httpStatus in 200..499
                }.map { it.result.ipIndex }.distinct().take(2)
                repeatLoop@ for (ip in comparisonIPs) {
                    for (attempt in 2..Zapret2SiteSearch.ATTEMPTS) {
                        for (google in listOf(false, true)) {
                            ensureActive()
                            if (!ready(TunnelState.status.value) ||
                                NetworkCheck.underlying(context).type.toString() != network ||
                                SystemClock.elapsedRealtime() - preparedAt >=
                                    Zapret2SiteSearch.TTL_MS - SNI_CONTROL_TIMEOUT_MILLIS) {
                                expired = true
                                break@repeatLoop
                            }
                            check(ip, attempt, google)
                            if (expired) break@repeatLoop
                        }
                    }
                }
                if (expired) {
                    statusText.text = context.getString(R.string.zapret2_site_search_expired)
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                progress.max = rows.size
                progress.progress = rows.size
                val report = Zapret2SiteSearch.sameIpControlReport(
                    network, prepared, ownControl, ownPrepared, rows, ipCount)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    context.getSystemService(ClipboardManager::class.java)?.let {
                        it.setPrimaryClip(ClipData.newPlainText(
                            "DPpass same-IP TLS SNI control", report))
                        true
                    } ?: false
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(if (copied)
                    R.string.zapret2_autotest_done
                    else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Same-IP SNI control cancelled")
            } finally {
                job = null
                siteInput.isEnabled = true
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    /**
     * The exact same two public API IPv4s are compared under TLS 1.2-only
     * versus TLS 1.3-only and the two original certificate-verified SNI
     * identities. No destination/IP/SNI spoofing for any live VPN traffic.
     */
    private fun startTLSVersionControl() {
        if (job?.isActive == true) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            return
        }
        val network = NetworkCheck.underlying(context).type.toString()
        runButton.isEnabled = false
        dnsButton.isEnabled = false
        matrixButton.isEnabled = false
        h3Button.isEnabled = false
        siteButton.isEnabled = false
        siteQuicButton.isEnabled = false
        youtubeHomeButton.isEnabled = false
        youtubeApiButton.isEnabled = false
        youtubeThumbnailButton.isEnabled = false
        youtubeApiSweepButton.isEnabled = false
        apiSniControlButton.isEnabled = false
        apiTLSVersionButton.isEnabled = false
        siteInput.isEnabled = false
        progress.visibility = View.VISIBLE
        progress.progress = 0
        resultText.visibility = View.GONE
        job = host.scope.launch {
            try {
                suspend fun probe(target: String, timeout: Int): Zapret2GoogleProbe =
                    try {
                        withContext(Dispatchers.IO) {
                            JniXrayRuntime.probeZapret2Google("plain", target, timeout)
                        }
                    } catch (_: LinkageError) { Zapret2GoogleProbe.unavailable() }
                val prepared = probe(
                    Zapret2SiteSearch.prepare(Zapret2SiteSearch.YOUTUBE_API_HOST),
                    DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers == 0) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val timestamp = SystemClock.elapsedRealtime()
                val count = prepared.dnsAnswers.coerceAtMost(Zapret2SiteSearch.MAX_IPS)
                val rows = mutableListOf<Zapret2GoogleAttempt>()
                progress.max = count * 2 * 2 * Zapret2SiteSearch.ATTEMPTS
                var expired = false
                outer@ for (ip in 0 until count) {
                    for (attempt in 1..Zapret2SiteSearch.ATTEMPTS) {
                        for (version in listOf(12, 13)) {
                            for (google in listOf(false, true)) {
                                ensureActive()
                                if (!ready(TunnelState.status.value) ||
                                    NetworkCheck.underlying(context).type.toString() != network ||
                                    SystemClock.elapsedRealtime() - timestamp >=
                                        Zapret2SiteSearch.TTL_MS - TLS_VERSION_TIMEOUT_MILLIS) {
                                    expired = true
                                    break@outer
                                }
                                val target = Zapret2SiteSearch.tlsVersionTrial(
                                    ip, attempt, version, google)
                                statusText.text = "IPv4 #$ip · TLS 1.$version · " +
                                    (if (google) "Google" else "YouTube API") +
                                    " · $attempt/3"
                                val response = probe(target, TLS_VERSION_TIMEOUT_MILLIS)
                                ensureActive()
                                if (response.outcome in setOf(
                                    "dns_not_prepared", "engine_off", "invalid_target")) {
                                    expired = true
                                    break@outer
                                }
                                rows += Zapret2GoogleAttempt("plain", attempt,
                                    response, target)
                                progress.progress = rows.size
                            }
                        }
                    }
                }
                if (expired) {
                    statusText.text = context.getString(R.string.zapret2_site_search_expired)
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launch
                }
                val report = Zapret2SiteSearch.tlsVersionReport(
                    network, prepared, rows, count)
                resultText.text = report
                resultText.visibility = View.VISIBLE
                val copied = try {
                    context.getSystemService(ClipboardManager::class.java)?.let {
                        it.setPrimaryClip(ClipData.newPlainText(
                            "DPpass same-IP TLS 1.2/1.3", report))
                        true
                    } ?: false
                } catch (_: SecurityException) { false }
                  catch (_: IllegalStateException) { false }
                statusText.text = context.getString(if (copied)
                    R.string.zapret2_autotest_done
                    else R.string.zapret2_autotest_copy_failed)
                host.toast(statusText.text)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("TLS version control cancelled")
            } finally {
                job = null
                siteInput.isEnabled = true
                runButton.isEnabled = ready(TunnelState.status.value)
                dnsButton.isEnabled = ready(TunnelState.status.value)
                matrixButton.isEnabled = ready(TunnelState.status.value)
                h3Button.isEnabled = ready(TunnelState.status.value)
                siteButton.isEnabled = ready(TunnelState.status.value)
                siteQuicButton.isEnabled = ready(TunnelState.status.value)
                youtubeHomeButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiButton.isEnabled = ready(TunnelState.status.value)
                youtubeThumbnailButton.isEnabled = ready(TunnelState.status.value)
                youtubeApiSweepButton.isEnabled = ready(TunnelState.status.value)
                apiSniControlButton.isEnabled = ready(TunnelState.status.value)
                apiTLSVersionButton.isEnabled = ready(TunnelState.status.value)
            }
        }
    }

    private companion object {
        const val REPEATS = 2
        const val TIMEOUT_MILLIS = 8_000
        const val DNS_TIMEOUT_MILLIS = 12_000
        const val MATRIX_TIMEOUT_MILLIS = 5_000
        const val H3_TIMEOUT_MILLIS = 8_000
        const val SITE_TIMEOUT_MILLIS = 6_000
        const val API_SWEEP_TIMEOUT_MILLIS = 5_000
        const val SNI_CONTROL_TIMEOUT_MILLIS = 5_000
        const val TLS_VERSION_TIMEOUT_MILLIS = 5_000
        val TOTAL: Int = Zapret2ProbeCatalog.targets.size *
            Zapret2ProbeCatalog.strategies.size * REPEATS
    }
}
