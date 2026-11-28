package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.text.InputFilter
import android.text.Editable
import android.text.TextWatcher
import android.os.SystemClock
import android.view.View
import android.text.InputType
import android.widget.EditText
import android.widget.Spinner
import android.widget.ArrayAdapter
import android.widget.AdapterView
import android.widget.ProgressBar
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.AppGraph
import com.dpsmpx.dppass.app.DptsBuildIdentity
import com.dpsmpx.dppass.app.DptsLocalSuite
import com.dpsmpx.dppass.app.DptsCompletedRun
import com.dpsmpx.dppass.app.DptsDiagnosticJob
import com.dpsmpx.dppass.app.DptsSavedScripts
import com.dpsmpx.dppass.app.DptsWorkspace
import com.dpsmpx.dppass.app.DptsCsv
import com.dpsmpx.dppass.app.DptsReportArchive
import com.dpsmpx.dppass.app.DptsReportCopy
import com.dpsmpx.dppass.app.DptsRunWindow
import com.dpsmpx.dppass.app.DptsSession
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
import com.dpsmpx.dppass.app.Zapret2NeuralModel
import com.dpsmpx.dppass.engine.xray.XrayResult
import com.dpsmpx.dppass.engine.xray.DptsInterruption
import com.dpsmpx.dppass.engine.xray.DptsPlan
import com.dpsmpx.dppass.engine.xray.DptsLearning
import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.DptsPresets
import com.dpsmpx.dppass.engine.xray.DptsCompileException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.withContext
import java.io.File
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
    private val dptsEditor = EditText(context).apply {
        hint = context.getString(R.string.dpts_script_hint)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE or
            InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS
        isSingleLine = false
        minLines = 7
        maxLines = 15
        filters = arrayOf(InputFilter.LengthFilter(DptsScript.MAX_SOURCE_LENGTH))
        setText(DptsSavedScripts.restoreEditor(
            context.getSharedPreferences("dpts_editor", Context.MODE_PRIVATE).all["source"],
            DptsPresets.scripts.getValue("YouTube · homepage")))
        contentDescription = context.getString(R.string.dpts_script_hint)
    }
    private var dptsPresets: List<DptsSavedScripts.ScriptEntry> = emptyList()
    private val personalScripts = DptsSavedScripts.restore(
        context.getSharedPreferences("dpts_saved_scripts", Context.MODE_PRIVATE).all)
    private val dptsNameInput = EditText(context).apply {
        hint = context.getString(R.string.dpts_name_hint)
        inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
        isSingleLine = true
        filters = arrayOf(InputFilter.LengthFilter(DptsSavedScripts.MAX_NAME_LENGTH))
        setText(DptsSavedScripts.restoreEditorName(
            context.getSharedPreferences("dpts_editor", Context.MODE_PRIVATE).all["name"]))
    }
    private val dptsPresetSpinner = Spinner(context)
    private val dptsDeleteButton = Ui.button(context, R.string.dpts_delete_script,
        Ui.Style.OUTLINE, R.drawable.ic_dns).apply { isEnabled = false }
    private val dptsLoadButton = Ui.button(context, R.string.dpts_load_preset,
        Ui.Style.OUTLINE, R.drawable.ic_dns)
    private val dptsFileButton = Ui.button(context, R.string.dpts_file_actions,
        Ui.Style.OUTLINE, R.drawable.ic_dns)
    private val dptsPreviewButton = Ui.button(context, R.string.dpts_preview_plan,
        Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val dptsRunButton = Ui.button(context, R.string.dpts_run_script,
        Ui.Style.PRIMARY, R.drawable.ic_speed)
    private val dptsSaveButton = Ui.button(context, R.string.dpts_save_script,
        Ui.Style.OUTLINE, R.drawable.ic_dns)
    private val dptsTrainButton = Ui.button(context, R.string.dpts_train_network,
        Ui.Style.OUTLINE, R.drawable.ic_speed)
    private val dptsStopButton = Ui.button(context, R.string.dpts_stop_script,
        Ui.Style.OUTLINE, R.drawable.ic_speed)
    private var matrixCsv: String? = null
    private var archiveReady = false
    private val archive by lazy { DptsReportArchive(File(context.noBackupFilesDir, "dpts-reports-v1")) }
    private var lastDptsRun: DptsCompletedRun? = null
    private var lastTrainingSubmitted = false
    private val progress = ProgressBar(context, null, android.R.attr.progressBarStyleHorizontal).apply {
        max = TOTAL
        visibility = View.GONE
    }
    private val statusText = Ui.text(context, R.style.Text_DPpass_Secondary)
    private val resultText = Ui.text(context, R.style.Text_DPpass_Body).apply {
        setTextIsSelectable(true)
        visibility = View.GONE
    }
    private val diagnostic = DptsDiagnosticJob(host.scope, failed = {
        invalidateDptsRun()
        // Do not publish exception messages, which may contain private data.
        matrixCsv = null
        archiveReady = false
        resultText.text = ""
        resultText.visibility = View.GONE
        statusText.text = context.getString(R.string.dpts_diagnostic_failed)
    }) {
        renderControls(TunnelState.status.value)
    }
    private var started = false

    private var activeSession: DptsSession? = null
    private var manualStopRequested = false

    private fun currentSession(offline: Boolean = false): DptsSession? {
        if (offline) {
            val snapshot = TunnelState.snapshot()
            if (snapshot.status != TunnelStatus.Idle) return null
            return DptsSession.offline(snapshot,
                runCatching { JniXrayRuntime.dptsGeneration() }.getOrNull())
        }
        if (!ready(TunnelState.status.value)) return null
        val underlying = NetworkCheck.underlying(context)
        return DptsSession.capture(underlying.type.toString(),
            underlying.network?.networkHandle,
            runCatching { JniXrayRuntime.dptsGeneration() }.getOrNull())
    }

    private class DiagnosticIncomplete : Exception()

    private fun requireDiagnosticSession() {
        val expected = activeSession ?: throw DiagnosticIncomplete()
        if (expected != currentSession(expected.offline)) throw DiagnosticIncomplete()
    }

    private suspend fun guardedProbe(method: String, target: String,
        timeout: Int): Zapret2GoogleProbe {
        currentCoroutineContext().ensureActive()
        requireDiagnosticSession()
        if (activeSession?.offline == true && !DptsLocalSuite.allowsOfflineProbe(method, target))
            throw DiagnosticIncomplete()
        val response = try {
            withContext(Dispatchers.IO) {
                JniXrayRuntime.probeZapret2Google(method, target, timeout)
            }
        } catch (_: LinkageError) {
            throw DiagnosticIncomplete()
        }
        currentCoroutineContext().ensureActive()
        requireDiagnosticSession()
        if (DptsRunWindow.invalidExecution(response.outcome)) throw DiagnosticIncomplete()
        return response
    }

    private fun launchDiagnostic(offline: Boolean = false, block: suspend CoroutineScope.(DptsSession) -> Unit) {
        manualStopRequested = false
        // Capture on the UI dispatcher at admission, not after scheduling.
        val session = currentSession(offline)
        if (session == null) {
            showIncompleteDpts()
            renderControls(TunnelState.status.value)
            return
        }
        diagnostic.start {
            try {
                activeSession = session
                requireDiagnosticSession()
                block(session)
            } catch (_: DiagnosticIncomplete) {
                ensureActive()
                showIncompleteDpts()
            } finally {
                activeSession = null
            }
        }
    }

    init {
        dptsEditor.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) = Unit
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {
                invalidateDptsRun()
                matrixCsv = null
                archiveReady = false
                resultText.text = ""
                resultText.visibility = View.GONE
                statusText.text = context.getString(R.string.dpts_choose_script)
                renderControls(TunnelState.status.value)
            }
            override fun afterTextChanged(s: Editable?) = Unit
        })
        dptsPresetSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?,
                position: Int, id: Long) {
                renderDeleteControl()
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {
                dptsDeleteButton.isEnabled = false
            }
        }
    }

    private fun invalidateDptsRun() {
        lastDptsRun = null
        lastTrainingSubmitted = false
        dptsTrainButton.isEnabled = false
    }

    private fun hasCurrentDptsRun(): Boolean {
        val run = lastDptsRun ?: return false
        return run.matches(dptsEditor.text.toString(), currentSession())
    }

    override fun content(): View = Ui.column(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Caption,
            context.getString(R.string.dpts_unified_note)), Ui.matchWidth())
        addView(dptsPresetSpinner, Ui.matchWidth())
        addView(dptsLoadButton.apply { setOnClickListener { loadSelectedScript() } },
            Ui.matchWidth())
        addView(dptsDeleteButton.apply { setOnClickListener { deleteSelectedScript() } },
            Ui.matchWidth())
        addView(dptsNameInput, Ui.matchWidth())
        addView(dptsEditor, Ui.matchWidth())
        addView(dptsSaveButton.apply { setOnClickListener { saveCurrentScript() } },
            Ui.matchWidth())
        addView(dptsFileButton.apply { setOnClickListener { showFileActions() } }, Ui.matchWidth())
        addView(dptsPreviewButton.apply { setOnClickListener { previewPlan() } }, Ui.matchWidth())
        addView(dptsRunButton.apply { setOnClickListener { startDptsScript() } },
            Ui.matchWidth())
        addView(dptsTrainButton.apply { setOnClickListener { trainFromLastScript() } },
            Ui.matchWidth())
        addView(dptsStopButton.apply { setOnClickListener {
            manualStopRequested = diagnostic.cancellable
            diagnostic.cancel()
            statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
        } }, Ui.matchWidth())
        addView(progress, Ui.matchWidth())
        addView(statusText, Ui.matchWidth())
        addView(resultText, Ui.matchWidth())
    }

    override fun onShown() {
        if (!started) {
            started = true
            refreshScriptCatalog()
            statusText.text = context.getString(R.string.dpts_choose_script)
        }
        render(TunnelState.status.value)
    }

    private fun renderControls(status: TunnelStatus) {
        val idle = !diagnostic.busy
        if (idle) progress.visibility = View.GONE
        dptsRunButton.isEnabled = idle && (ready(status) || offlineAvailable(status))
        dptsLoadButton.isEnabled = idle
        renderDeleteControl()
        dptsSaveButton.isEnabled = idle
        dptsFileButton.isEnabled = idle
        dptsPreviewButton.isEnabled = idle
        dptsTrainButton.isEnabled = idle && ready(status) && !lastTrainingSubmitted &&
            hasCurrentDptsRun()
        dptsStopButton.isEnabled = diagnostic.cancellable
        dptsEditor.isEnabled = idle
        dptsPresetSpinner.isEnabled = idle
        dptsNameInput.isEnabled = idle
    }

    override fun render(status: TunnelStatus) {
        if (!ready(status)) {
            invalidateDptsRun()
            val runningOffline = activeSession?.offline == true && status == TunnelStatus.Idle
            if (diagnostic.cancellable && !runningOffline) diagnostic.cancel()
        } else if (activeSession?.offline == true && diagnostic.cancellable) {
            diagnostic.cancel()
        }
        renderControls(status)
        if (!diagnostic.busy && !ready(status) && !offlineAvailable(status)) {
            statusText.text = context.getString(R.string.dpts_connection_or_local)
        }
    }

    override fun onHidden() {
        manualStopRequested = false
        diagnostic.cancel()
        invalidateDptsRun()
        // Persist only the editable draft, never probe results or IPs.
        persistEditor()
    }

    private fun persistEditor() {
        context.getSharedPreferences("dpts_editor", Context.MODE_PRIVATE).edit()
            .putString("source", dptsEditor.text.toString())
            .putString("name", dptsNameInput.text.toString()).apply()
    }

    private fun ready(status: TunnelStatus): Boolean =
        host.prefs.zapret2Backend == Zapret2Backend.VPN_SERVICE &&
            status is TunnelStatus.Connected && status.profileId == ServerlessPlan.PROFILE_ID

    private fun offlineAvailable(status: TunnelStatus): Boolean =
        status == TunnelStatus.Idle && DptsLocalSuite.fromScript(dptsEditor.text.toString()) != null

    /** The former one-off diagnostic buttons now exist only as DPTS suite presets. */
    private fun launchScriptSuite(plan: DptsPlan) {
        when (plan.suite) {
            "google_youtube" -> start()
            "dns_compare" -> start(dnsComparison = true)
            "ip_matrix" -> startMatrix()
            "h3_api" -> startH3()
            "site_https" -> startSiteSearch(plan.host, quic = false)
            "site_quic" -> startSiteSearch(plan.host, quic = true)
            "api_ipv4_sweep" -> startYoutubeApiSweep()
            "sni_control" -> startSameIpSniControl()
            "tls_versions" -> startTLSVersionControl()
            "local_http_hostcase" -> startLocalHttpHostCase()
            "local_http_combined" -> startLocalSuite(DptsLocalSuite.HTTP_COMBINED)
            "local_tls" -> startLocalTLS()
            "local_tls_chain" -> startLocalSuite(DptsLocalSuite.TLS_CHAIN)
            "local_acceptance" -> startLocalSuite(DptsLocalSuite.ACCEPTANCE)
            else -> {
                statusText.text = context.getString(R.string.dpts_suite_unsupported)
            }
        }
    }

    private fun startLocalTLS() = startLocalSuite(DptsLocalSuite.TLS)

    private fun startLocalHttpHostCase() = startLocalSuite(DptsLocalSuite.HTTP)

    // Both fixed local presets use the same finite execution and report
    // path. No new buttons, user-defined endpoints or training evidence.
    private fun startLocalSuite(suite: DptsLocalSuite) {
        val source = dptsEditor.text.toString()
        progress.visibility = View.VISIBLE
        progress.max = suite.cases.size
        progress.progress = 0
        resultText.visibility = View.GONE
        launchDiagnostic(offline = TunnelState.status.value == TunnelStatus.Idle) { session ->
            val rows = mutableListOf<Zapret2GoogleProbe>()
            var buildIdentity: DptsBuildIdentity? = null
            fun interrupted(reason: DptsInterruption) {
                invalidateDptsRun()
                if (source != dptsEditor.text.toString()) return
                val report = suite.report(rows, reason, buildIdentity)
                archiveReady = true
                resultText.text = report
                resultText.visibility = View.VISIBLE
                statusText.text = context.getString(R.string.dpts_stopped)
                if (session == currentSession(session.offline) &&
                    !copyReport("DPpass local partial", report)) {
                    statusText.text = context.getString(R.string.zapret2_autotest_copy_failed)
                }
            }
            try {
                statusText.text = "DPTS: APK SHA-256"
                buildIdentity = withContext(Dispatchers.IO) {
                    val job = currentCoroutineContext()
                    val app = context.applicationInfo
                    DptsBuildIdentity.capture(File(app.sourceDir),
                        app.splitSourceDirs?.size ?: 0, AppGraph.appVersion(context)) {
                        job.ensureActive()
                    }
                }
                ensureActive()
                requireDiagnosticSession()
                // The monotonic window includes all JNI overhead, not just
                // the configured per-probe socket timeout.
                val startedAt = SystemClock.elapsedRealtime()
                val budget = suite.budgetMs + 5000L
                for (case in suite.cases) {
                    ensureActive()
                    requireDiagnosticSession()
                    if (SystemClock.elapsedRealtime() - startedAt >= budget - 5000L) {
                        interrupted(DptsInterruption.BUDGET_EXPIRED)
                        return@launchDiagnostic
                    }
                    statusText.text = "DPTS: " + case.label
                    val row = guardedProbe(case.method, case.target, 5000)
                    if (SystemClock.elapsedRealtime() - startedAt >= budget) {
                        interrupted(DptsInterruption.BUDGET_EXPIRED)
                        return@launchDiagnostic
                    }
                    rows += row
                    progress.progress = rows.size
                }
                publishCompletedReport(suite.reportLabel, suite.report(rows, buildIdentity = buildIdentity), R.string.dpts_copied)
            } catch (_: DiagnosticIncomplete) {
                ensureActive()
                interrupted(if (session != currentSession(session.offline)) DptsInterruption.SESSION_CHANGED
                    else DptsInterruption.EXECUTION_ERROR)
            } catch (cancelled: CancellationException) {
                if (manualStopRequested && session == currentSession(session.offline) &&
                    source == dptsEditor.text.toString()) {
                    interrupted(DptsInterruption.USER_STOP)
                } else {
                    invalidateDptsRun()
                    statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                }
                throw cancelled
            }
        }
    }

    private fun selectedScript(): DptsSavedScripts.ScriptEntry? =
        dptsPresets.getOrNull(dptsPresetSpinner.selectedItemPosition)

    private fun refreshScriptCatalog(chosen: DptsSavedScripts.ScriptId? = selectedScript()?.id) {
        dptsPresets = DptsSavedScripts.catalog(DptsPresets.scripts, personalScripts)
        val labels = dptsPresets.map { entry ->
            if (entry.id.personal)
                context.getString(R.string.dpts_personal_label, entry.id.name)
            else entry.id.name
        }
        dptsPresetSpinner.adapter = ArrayAdapter(context,
            android.R.layout.simple_spinner_item, labels).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        dptsPresetSpinner.setSelection(dptsPresets.indexOfFirst { it.id == chosen }
            .coerceAtLeast(0))
        renderDeleteControl()
    }

    private fun renderDeleteControl() {
        dptsDeleteButton.isEnabled = !diagnostic.busy &&
            selectedScript()?.id?.personal == true
    }

    private fun deleteSelectedScript() {
        if (diagnostic.busy) return
        val entry = selectedScript() ?: return
        val key = DptsSavedScripts.preferenceKey(entry.id) ?: return
        AlertDialog.Builder(context)
            .setTitle(R.string.dpts_delete_script)
            .setMessage(context.getString(R.string.dpts_delete_confirm, entry.id.name))
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(R.string.dpts_delete_script) { _, _ ->
                if (!diagnostic.busy && personalScripts[entry.id.name] == entry.source) {
                    context.getSharedPreferences("dpts_saved_scripts", Context.MODE_PRIVATE)
                        .edit().remove(key).apply()
                    personalScripts.remove(entry.id.name)
                    refreshScriptCatalog()
                    // The editable text remains available even after deleting
                    // the saved catalog entry. Built-ins are never removed.
                    statusText.text = context.getString(R.string.dpts_script_deleted)
                }
            }.show()
    }

    private fun loadSelectedScript() {
        if (diagnostic.busy) return
        val entry = selectedScript() ?: return
        dptsNameInput.setText(entry.id.name)
        dptsEditor.setText(entry.source)
        invalidateDptsRun()
        persistEditor()
        statusText.text = context.getString(R.string.dpts_script_loaded)
    }

    private fun saveCurrentScript() {
        if (diagnostic.busy) return
        val name = dptsNameInput.text.toString().trim()
        val source = dptsEditor.text.toString()
        if (!DptsSavedScripts.validDraft(name, source)) {
            statusText.text = context.getString(R.string.dpts_invalid_save)
            return
        }
        if (name !in personalScripts && personalScripts.size >= DptsSavedScripts.MAX_SCRIPTS) {
            statusText.text = context.getString(R.string.dpts_save_limit)
            return
        }
        // Drafts may be saved before they compile; no source is executed
        // during save/load and the runner always checks the complete grammar.
        val id = DptsSavedScripts.ScriptId(name, true)
        val key = DptsSavedScripts.preferenceKey(id) ?: return
        personalScripts[name] = source
        context.getSharedPreferences("dpts_saved_scripts", Context.MODE_PRIVATE)
            .edit().putString(key, source).apply()
        persistEditor()
        refreshScriptCatalog(id)
        statusText.text = context.getString(R.string.dpts_script_saved)
    }

    private fun showFileActions() {
        if (diagnostic.busy) return
        val actions = mutableListOf<Pair<Int, () -> Unit>>(
            R.string.dpts_builder_title to {
                DptsBuilderDialog.show(context) { source ->
                    offerImportedScript(source, R.string.dpts_builder_title)
                }
            },
            R.string.dpts_builder_append to {
                val original = dptsEditor.text.toString()
                DptsBuilderDialog.show(context, original) { combined ->
                    if (!diagnostic.busy && dptsEditor.text.toString() == original) {
                        // The preview's explicit Insert action confirms this append;
                        // keep the current saved-script name and editable source.
                        dptsEditor.setText(combined)
                        persistEditor()
                        statusText.text = context.getString(R.string.dpts_script_loaded)
                    }
                }
            },
            R.string.dpts_import_file to { host.pickDptsFile() },
            R.string.dpts_export_file to {
                host.saveDocument("DPpass-script.dpts.txt", dptsEditor.text.toString())
            },
            R.string.dpts_share_script to { shareText(dptsEditor.text.toString()) },
            R.string.dpts_archive_title to { openArchive() },
        )
        if (resultText.visibility == View.VISIBLE && resultText.text.isNotBlank()) {
            actions += R.string.dpts_export_report to {
                host.saveDocument("DPpass-DPTS-report.txt", resultText.text.toString())
            }
            actions += R.string.dpts_share_report to { shareText(resultText.text.toString()) }
            if (archiveReady) {
                val report = resultText.text.toString()
                val csv = matrixCsv
                actions += R.string.dpts_archive_save to {
                    if (!diagnostic.busy && archiveReady && resultText.text.toString() == report && matrixCsv == csv) {
                        saveArchiveReport(report, csv)
                    }
                }
            }
            matrixCsv?.let { csv ->
                actions += R.string.dpts_export_csv to {
                    host.saveDocument("DPpass-DPTS-matrix.csv", csv)
                }
            }
        }
        AlertDialog.Builder(context)
            .setTitle(R.string.dpts_file_actions)
            .setItems(actions.map { context.getString(it.first) }.toTypedArray()) { _, index ->
                if (!diagnostic.busy) actions[index].second()
            }.show()
    }

    private var archiveBusy = false

    private fun saveArchiveReport(report: String, csv: String?) {
        if (archiveBusy) return
        archiveBusy = true
        host.scope.launch {
            try {
                val saved = withContext(Dispatchers.IO) { archive.save(report, csv) }
                host.toast(context.getString(if (saved) R.string.dpts_archive_saved else R.string.dpts_archive_failed))
            } finally { archiveBusy = false }
        }
    }

    private fun openArchive() {
        if (archiveBusy || diagnostic.busy) return
        archiveBusy = true
        host.scope.launch {
            try {
                val records = withContext(Dispatchers.IO) { archive.list() }
                if (records == null || records.isEmpty()) {
                    host.toast(context.getString(if (records == null) R.string.dpts_archive_unavailable else R.string.dpts_archive_empty))
                    return@launch
                }
                val date = SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.getDefault())
                val labels = records.map { record ->
                    date.format(Date(record.time)) + " · " + record.report.lineSequence().firstOrNull().orEmpty().take(100) +
                        (if (record.csv != null) " · CSV" else "")
                }
                AlertDialog.Builder(context).setTitle(R.string.dpts_archive_title)
                    .setItems(labels.toTypedArray()) { _, index -> showArchivedReport(records[index]) }
                    .setNegativeButton(android.R.string.cancel, null).show()
            } finally { archiveBusy = false }
        }
    }

    private fun showArchivedReport(record: DptsReportArchive.Record) {
        if (archiveBusy || diagnostic.busy) return
        val actions = mutableListOf<Pair<Int, () -> Unit>>(
            R.string.dpts_archive_view to {
                AlertDialog.Builder(context).setTitle(R.string.dpts_archive_view)
                    .setMessage(record.report).setPositiveButton(android.R.string.ok, null).show()
            },
            R.string.dpts_archive_copy to {
                host.toast(context.getString(if (copyReport("DPpass archived DPTS", record.report))
                    R.string.dpts_archive_copied else R.string.zapret2_autotest_copy_failed))
            },
            R.string.dpts_export_report to { host.saveDocument("DPpass-DPTS-${record.id}.txt", record.report) },
            R.string.dpts_share_report to { shareText(record.report) },
        )
        record.csv?.let { csv ->
            actions += R.string.dpts_export_csv to { host.saveDocument("DPpass-DPTS-${record.id}.csv", csv) }
        }
        actions += R.string.dpts_archive_delete to {
            AlertDialog.Builder(context).setTitle(R.string.dpts_archive_delete)
                .setMessage(R.string.dpts_archive_delete_confirm)
                .setNegativeButton(android.R.string.cancel, null)
                .setPositiveButton(R.string.dpts_archive_delete) { _, _ ->
                    if (!archiveBusy) {
                        archiveBusy = true
                        host.scope.launch {
                            try {
                                val removed = withContext(Dispatchers.IO) { archive.delete(record) }
                                host.toast(context.getString(if (removed) R.string.dpts_archive_deleted else R.string.dpts_archive_unavailable))
                            } finally { archiveBusy = false }
                        }
                    }
                }.show()
        }
        AlertDialog.Builder(context).setTitle(R.string.dpts_archive_title)
            .setItems(actions.map { context.getString(it.first) }.toTypedArray()) { _, index ->
                if (!diagnostic.busy) actions[index].second()
            }.setNegativeButton(android.R.string.cancel, null).show()
    }

    private fun shareText(text: String) {
        val intent = Intent(Intent.ACTION_SEND).setType("text/plain")
            .putExtra(Intent.EXTRA_TEXT, text)
        try {
            context.startActivity(Intent.createChooser(intent, context.getString(R.string.dpts_file_actions)))
        } catch (_: android.content.ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_system_screen))
        }
    }

    internal fun offerImportedScript(source: String, title: Int = R.string.dpts_import_file) {
        if (diagnostic.busy) return
        fun replaceDraft() {
            if (diagnostic.busy) return
            dptsNameInput.setText("")
            dptsEditor.setText(source)
            persistEditor()
            statusText.text = context.getString(R.string.dpts_script_loaded)
        }
        if (dptsEditor.text.isBlank() || dptsEditor.text.toString() == source) replaceDraft()
        else AlertDialog.Builder(context)
            .setTitle(title)
            .setMessage(R.string.dpts_replace_editor)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok) { _, _ -> replaceDraft() }
            .show()
    }

    private fun previewPlan() {
        if (diagnostic.busy) return
        val plan = try {
            DptsScript.compile(dptsEditor.text.toString())
        } catch (error: DptsCompileException) {
            AlertDialog.Builder(context).setTitle(R.string.dpts_preview_plan)
                .setMessage(error.message.orEmpty()).setPositiveButton(android.R.string.ok, null).show()
            return
        }
        val summary = DptsWorkspace.preview(plan)
        AlertDialog.Builder(context).setTitle(R.string.dpts_preview_plan)
            .setMessage(summary).setPositiveButton(android.R.string.ok, null).show()
    }

    private fun copyReport(label: String, report: String): Boolean =
        DptsReportCopy.attempt {
            val clipboard = context.getSystemService(ClipboardManager::class.java)
                ?: return@attempt false
            clipboard.setPrimaryClip(ClipData.newPlainText(label, report))
            true
        }

    private suspend fun publishCompletedReport(label: String, report: String,
        successMessage: Int = R.string.zapret2_autotest_done) {
        currentCoroutineContext().ensureActive()
        requireDiagnosticSession()
        archiveReady = true
        resultText.text = report
        resultText.visibility = View.VISIBLE
        val copied = copyReport(label, report)
        statusText.text = context.getString(
            if (copied) successMessage else R.string.zapret2_autotest_copy_failed)
        host.toast(statusText.text)
    }

    /**
     * Training is opt-in and supervised by native evidence, never by the
     * script itself: 3/3 independent verified YouTube HTML responses on
     * two identical pinned IPs for the candidate, versus a failing plain.
     * HTTP 4xx/TLS handshake alone (as in the 0/32 API log) is ineligible.
     */
    private fun appendTrainingLog(event: String) {
        // Training is a separate explicit user action after the completed
        // report. Keep its outcome in the same automatically copied log.
        val previous = resultText.text.toString().take(64_000)
        val updated = previous.trimEnd() + "\n\n" + statusText.text.toString() + 
            "\nTRAINING: " + event + "\n"
        resultText.text = updated
        resultText.visibility = View.VISIBLE
        if (!copyReport("DPpass DPTS + training", updated)) {
            host.toast(context.getString(R.string.dpts_training_copy_failed))
        }
    }

    private fun trainFromLastScript() {
        if (diagnostic.busy || lastTrainingSubmitted) return
        val run = lastDptsRun
        if (run == null || !run.matches(dptsEditor.text.toString(), currentSession())) {
            invalidateDptsRun()
            statusText.text = context.getString(R.string.dpts_train_no_run)
            appendTrainingLog("not_applied reason=no_matching_completed_run")
            return
        }
        if (!run.trainingNetworkSupported) {
            statusText.text = context.getString(R.string.dpts_train_no_run)
            appendTrainingLog("not_applied reason=unsupported_training_network")
            return
        }
        val evidence = DptsLearning.analyze(run.plan, run.rows)
        val candidates = evidence.winners
        if (candidates.isEmpty()) {
            statusText.text = context.getString(when (evidence.reason) {
                "learning_disabled_in_script" -> R.string.dpts_train_disabled
                "verified_single_ip_only" -> R.string.dpts_train_partial
                "transport_only_not_content" -> R.string.dpts_train_transport_only
                "no_verified_transport" -> R.string.dpts_train_no_transport
                else -> R.string.dpts_train_no_evidence
            })
            appendTrainingLog("not_applied reason=" + evidence.reason + " " + evidence.report())
            return
        }
        val kind = Zapret2NeuralModel.Kind.STRATEGY
        // Generate once if the user has not created a local strategy model.
        // Pin exact durable bytes before native mutation, never afterwards.
        // A regenerated or independently persisted model must not be replaced
        // using a later baseline that was not part of this training action.
        val expected = Zapret2NeuralModel.readVerified(context, kind) ?: run {
            val generated = Zapret2NeuralModel.generate(context, kind,
                Zapret2NeuralModel.DEFAULT_HIDDEN).getOrNull()
            if (generated == null ||
                runCatching { JniXrayRuntime.configureZapret2NeuralModel(generated) }
                    .getOrNull() != XrayResult.Ok) {
                statusText.text = context.getString(R.string.dpts_train_model_error)
                appendTrainingLog("not_applied reason=local_model_unavailable")
                return
            }
            generated
        }
        if (!run.matches(dptsEditor.text.toString(), currentSession())) {
            invalidateDptsRun()
            statusText.text = context.getString(R.string.dpts_train_no_run)
            appendTrainingLog("not_applied reason=session_changed_before_training")
            return
        }
        if (Zapret2NeuralModel.readVerified(context, kind)?.contentEquals(expected) != true) {
            statusText.text = context.getString(R.string.dpts_train_model_error)
            appendTrainingLog("not_applied reason=model_changed_before_training")
            return
        }
        val trained = runCatching {
            JniXrayRuntime.trainZapret2NeuralFromDPTS(run.network, candidates, run.generation)
        }.getOrNull()
        if (trained != XrayResult.Ok) {
            statusText.text = context.getString(R.string.dpts_train_model_error)
            appendTrainingLog("not_applied reason=native_training_rejected")
            return
        }
        // The native head is already updated; prevent a second click from
        // training twice even if durable storage fails.
        lastTrainingSubmitted = true
        dptsTrainButton.isEnabled = false
        val snapshot = runCatching {
            JniXrayRuntime.snapshotZapret2NeuralModel()
        }.getOrNull()
        val stored = snapshot != null &&
            Zapret2NeuralModel.storeLearnedSnapshot(context, kind, snapshot, expected)
        if (!stored) {
            statusText.text = context.getString(R.string.dpts_train_save_error)
            appendTrainingLog("updated_in_memory snapshot_not_saved")
            return
        }
        val ack = runCatching {
            JniXrayRuntime.acknowledgeZapret2NeuralModel(snapshot)
        }.getOrNull()
        val persisted = ack == XrayResult.Ok
        statusText.text = if (persisted)
            context.getString(R.string.dpts_train_success, candidates.joinToString(", "))
        else context.getString(R.string.dpts_train_ack_error)
        appendTrainingLog(if (persisted)
            "local_verified_html_head_updated persisted=true eligible_methods=" +
                candidates.joinToString(",") + " " + evidence.report()
            else "local_verified_html_head_updated snapshot_persisted_ack_failed")
    }

    private fun start(dnsComparison: Boolean = false) {
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val quic = host.prefs.zapret2VpnForceTcp
        val targets = if (dnsComparison) Zapret2ProbeCatalog.dnsTargets else Zapret2ProbeCatalog.targets
        val strategies = if (dnsComparison) Zapret2ProbeCatalog.dnsStrategies else Zapret2ProbeCatalog.strategies
        val timeout = if (dnsComparison) DNS_TIMEOUT_MILLIS else TIMEOUT_MILLIS
        val total = targets.size * strategies.size * REPEATS
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        val rows = mutableListOf<Zapret2GoogleAttempt>()
        progress.max = total
        progress.progress = 0
        progress.visibility = View.VISIBLE
        resultText.visibility = View.GONE
        statusText.text = context.getString(R.string.zapret2_autotest_progress,
            0, total, targets.first(), strategies.first(), 0, REPEATS)
        launchDiagnostic { session ->
            val network = session.network
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
                            val response = guardedProbe(strategy, target, timeout)
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
                publishCompletedReport(if (dnsComparison) "DPpass protected DoH comparison" else "DPpass Zapret2 HTTPS diagnostics", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Google autotest cancelled")
            }
        }
    }

    /** All addresses, two TCP application protocols, and a separate QUIC handshake.
     * Duplicate short DNS fingerprints are tested once to avoid repeating the
     * same IPv4 positions. The test remains opt-in and has no AUTO feedback.
     */
    private fun startMatrix() {
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        progress.visibility = View.VISIBLE
        progress.max = Zapret2ProbeCatalog.matrixProviders.size
        progress.progress = 0
        resultText.visibility = View.GONE
        launchDiagnostic { session ->
            val network = session.network
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
                    val response = guardedProbe("plain", id, DNS_TIMEOUT_MILLIS)
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
                    val response = guardedProbe(trial.second, trial.first, MATRIX_TIMEOUT_MILLIS)
                    ensureActive()
                    rows += Zapret2GoogleAttempt(trial.second, 1, response, trial.first)
                    progress.progress = done + 1
                }
                val report = Zapret2MatrixReport.render(stamp, network, rows)
                publishCompletedReport("DPpass IPv4 TLS HTTP2 QUIC", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("IP matrix cancelled")
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
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val stamp = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ssXXX", Locale.ROOT).format(Date())
        progress.max = 1
        progress.progress = 0
        progress.visibility = View.VISIBLE
        resultText.visibility = View.GONE
        launchDiagnostic { session ->
            val network = session.network
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
                    val result = guardedProbe("plain", target, timeout)
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
                if (expired) {
                    showIncompleteDpts()
                    return@launchDiagnostic
                }
                val report = Zapret2H3Report.render(stamp, network, rows)
                progress.max = done.coerceAtLeast(1)
                progress.progress = done
                publishCompletedReport("DPpass protected HTTP3 YouTube API", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("YouTube H3 diagnostic cancelled")
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
    private fun startSiteSearch(hostname: String, quic: Boolean) {
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        val domain = Zapret2SiteSearch.normalizedHost(hostname)
        if (domain == null) {
            statusText.text = context.getString(R.string.zapret2_site_search_invalid)
            host.toast(statusText.text)
            return
        }
        val methods = if (quic) Zapret2SiteSearch.quicMethods else Zapret2SiteSearch.tcpMethods
        progress.visibility = View.VISIBLE
        progress.progress = 0
        progress.max = methods.size * Zapret2SiteSearch.MAX_IPS * Zapret2SiteSearch.ATTEMPTS
        resultText.visibility = View.GONE
        statusText.text = "DoH · $domain"
        launchDiagnostic { session ->
            val network = session.network
            try {
                val prepared = guardedProbe("plain", Zapret2SiteSearch.prepare(domain), DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launchDiagnostic
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
                            val response = guardedProbe(method, target, SITE_TIMEOUT_MILLIS)
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
                    return@launchDiagnostic
                }
                val selection = Zapret2SiteSearch.recommend(domain, ipCount, rows, quic)
                // Script suites do not apply a live AUTO strategy implicitly.
                // The explicit "Train" button has its own stronger evidence
                // gate and changes only the contextual MLP, not the route.
                val commit: Zapret2GoogleProbe? = null
                val report = Zapret2SiteSearch.report(
                    domain, network, quic, prepared, rows, selection, commit)
                publishCompletedReport("DPpass site strategy search", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Any-site strategy search cancelled")
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
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            host.toast(statusText.text)
            return
        }
        resultText.visibility = View.GONE
        progress.visibility = View.VISIBLE
        progress.progress = 0
        statusText.text = "DoH · ${Zapret2SiteSearch.YOUTUBE_API_HOST}"
        launchDiagnostic { session ->
            val network = session.network
            try {
                val prepared = guardedProbe("plain",
                            Zapret2SiteSearch.prepare(Zapret2SiteSearch.YOUTUBE_API_HOST),
                            DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launchDiagnostic
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
                        val response = guardedProbe(method, target, API_SWEEP_TIMEOUT_MILLIS)
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
                    return@launchDiagnostic
                }
                // Confirm up to two transport-positive IP/protocol/method
                // tuples using independent connections. This is evidence
                // only and never passes through AUTO's commit interface.
                val candidates = rows.filter {
                    it.result.tlsStage == "tls_verified" &&
                        it.result.httpStatus in 200..499
                }.take(2).toList()
                for (candidate in candidates) {
                    for (attempt in 2..Zapret2SiteSearch.ATTEMPTS) {
                        ensureActive()
                        if (!ready(TunnelState.status.value) ||
                            NetworkCheck.underlying(context).type.toString() != network ||
                            SystemClock.elapsedRealtime() - startedAt >=
                                Zapret2SiteSearch.TTL_MS - API_SWEEP_TIMEOUT_MILLIS) {
                            showIncompleteDpts()
                            return@launchDiagnostic
                        }
                        val target = Zapret2SiteSearch.apiSweepTrial(
                            candidate.result.ipIndex, attempt, candidate.result.protocol)
                        statusText.text = "API IPv4 #${candidate.result.ipIndex} · " +
                            "${candidate.result.protocol} / ${candidate.strategy} · $attempt/3"
                        val response = guardedProbe(candidate.strategy, target, API_SWEEP_TIMEOUT_MILLIS)
                        ensureActive()
                        rows += Zapret2GoogleAttempt(candidate.strategy, attempt,
                            response, target)
                        progress.progress = rows.size
                    }
                }
                progress.max = rows.size
                progress.progress = rows.size
                val report = Zapret2SiteSearch.apiSweepReport(
                    network, prepared, rows, ipCount)
                publishCompletedReport("DPpass API IP/H2 sweep", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("API IPv4/H2 sweep cancelled")
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
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            return
        }
        progress.visibility = View.VISIBLE
        progress.progress = 0
        resultText.visibility = View.GONE
        statusText.text = "DoH · API и Google TLS"
        launchDiagnostic { session ->
            val network = session.network
            try {
                suspend fun probe(method: String, target: String, ms: Int):
                    Zapret2GoogleProbe = guardedProbe(method, target, ms)
                val prepared = probe("plain", Zapret2SiteSearch.prepare(
                    Zapret2SiteSearch.YOUTUBE_API_HOST), DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers < 1) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launchDiagnostic
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
                    return@launchDiagnostic
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
                    return@launchDiagnostic
                }
                progress.max = rows.size
                progress.progress = rows.size
                val report = Zapret2SiteSearch.sameIpControlReport(
                    network, prepared, ownControl, ownPrepared, rows, ipCount)
                publishCompletedReport("DPpass same-IP TLS SNI control", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("Same-IP SNI control cancelled")
            }
        }
    }

    /**
     * The exact same two public API IPv4s are compared under TLS 1.2-only
     * versus TLS 1.3-only and the two original certificate-verified SNI
     * identities. No destination/IP/SNI spoofing for any live VPN traffic.
     */
    private fun startTLSVersionControl() {
        if (diagnostic.busy) return
        if (!ready(TunnelState.status.value)) {
            statusText.text = context.getString(R.string.zapret2_autotest_need_connection)
            return
        }
        progress.visibility = View.VISIBLE
        progress.progress = 0
        resultText.visibility = View.GONE
        launchDiagnostic { session ->
            val network = session.network
            try {
                suspend fun probe(target: String, timeout: Int): Zapret2GoogleProbe =
                    guardedProbe("plain", target, timeout)
                val prepared = probe(
                    Zapret2SiteSearch.prepare(Zapret2SiteSearch.YOUTUBE_API_HOST),
                    DNS_TIMEOUT_MILLIS)
                ensureActive()
                if (prepared.outcome != "dns_ready" || prepared.dnsAnswers == 0) {
                    statusText.text = context.getString(R.string.zapret2_site_search_dns_fail) +
                        " (${prepared.outcome})"
                    resultText.text = statusText.text
                    resultText.visibility = View.VISIBLE
                    return@launchDiagnostic
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
                                statusText.text = "IPv4 #$ip · TLS 1.${version % 10} · " +
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
                    return@launchDiagnostic
                }
                val report = Zapret2SiteSearch.tlsVersionReport(
                    network, prepared, rows, count)
                publishCompletedReport("DPpass same-IP TLS 1.2/1.3", report)
            } catch (_: CancellationException) {
                statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                throw CancellationException("TLS version control cancelled")
            }
        }
    }


    /**
     * DPTS executes a statically validated, deterministic matrix through
     * the existing protected Xray diagnostic adapter. No script-controlled
     * URLs, sockets, code execution, application routes or AUTO commits.
     */
    private fun startDptsScript() {
        if (diagnostic.busy) return
        // Even a failed compile or unavailable connection replaces the previous run.
        invalidateDptsRun()
        matrixCsv = null
        archiveReady = false
        resultText.text = ""
        resultText.visibility = View.GONE
        val source = dptsEditor.text.toString()
        val plan = try {
            DptsScript.compile(source)
        } catch (e: DptsCompileException) {
            statusText.text = e.message ?: "Invalid DPTS script"
            resultText.text = statusText.text
            resultText.visibility = View.VISIBLE
            return
        } catch (e: IllegalArgumentException) {
            statusText.text = e.message ?: "Invalid DPTS script"
            resultText.text = statusText.text
            resultText.visibility = View.VISIBLE
            return
        }
        val status = TunnelState.status.value
        if (!ready(status) && !(status == TunnelStatus.Idle && DptsLocalSuite.fromId(plan.suite) != null)) {
            statusText.text = context.getString(R.string.dpts_connection_or_local)
            host.toast(statusText.text)
            return
        }
        persistEditor()
        if (plan.suite != null) {
            launchScriptSuite(plan)
            return
        }
        progress.visibility = View.VISIBLE
        progress.max = plan.probes.size
        progress.progress = 0
        resultText.visibility = View.GONE
        statusText.text = "DPTS: DoH · ${plan.host}"
        launchDiagnostic { session ->
            val network = session.network
            val rows = mutableListOf<Zapret2GoogleAttempt>()
            var preparation: Zapret2GoogleProbe? = null
            fun interrupted(reason: DptsInterruption) {
                invalidateDptsRun()
                val prepared = preparation
                if (prepared == null) {
                    showIncompleteDpts()
                    return
                }
                // Only previously accepted rows are retained. Never append a
                // result returned after the session or deadline changed.
                val report = DptsScript.report(plan, network, prepared, rows, reason)
                matrixCsv = DptsCsv.render(plan, network, prepared, rows, reason)
                archiveReady = true
                resultText.text = report
                resultText.visibility = View.VISIBLE
                statusText.text = context.getString(R.string.dpts_stopped)
                // Copy a deliberate stop or bounded failure in the same
                // session. A stale network must not replace the clipboard.
                if (session == currentSession() && source == dptsEditor.text.toString()) {
                    if (!copyReport("DPpass DPTS partial", report)) {
                        statusText.text = context.getString(R.string.zapret2_autotest_copy_failed)
                    }
                }
            }
            try {
                val window = DptsRunWindow(SystemClock.elapsedRealtime(), DNS_TIMEOUT_MILLIS)
                val prepared = guardedProbe("plain",
                            Zapret2SiteSearch.prepare(plan.host), DNS_TIMEOUT_MILLIS)
                ensureActive()
                preparation = prepared
                if (session != currentSession()) {
                    interrupted(DptsInterruption.SESSION_CHANGED)
                    return@launchDiagnostic
                }
                if (!window.canFinish(SystemClock.elapsedRealtime())) {
                    interrupted(DptsInterruption.BUDGET_EXPIRED)
                    return@launchDiagnostic
                }
                if (!DptsScript.preparationValid(plan, prepared)) {
                    interrupted(DptsInterruption.DNS_PREPARATION_FAILED)
                    return@launchDiagnostic
                }
                for ((index, probe) in plan.probes.withIndex()) {
                    ensureActive()
                    if (session != currentSession()) {
                        interrupted(DptsInterruption.SESSION_CHANGED)
                        return@launchDiagnostic
                    }
                    if (!window.canStart(SystemClock.elapsedRealtime(), probe.timeoutMs)) {
                        interrupted(DptsInterruption.BUDGET_EXPIRED)
                        return@launchDiagnostic
                    }
                    statusText.text = "DPTS: ${plan.title} · ${index + 1}/${plan.probes.size}" +
                        " · ${probe.phase}/${probe.method} IPv4 #${probe.ipIndex}"
                    val response = guardedProbe(probe.method, probe.target, probe.timeoutMs)
                    ensureActive()
                    if (session != currentSession()) {
                        interrupted(DptsInterruption.SESSION_CHANGED)
                        return@launchDiagnostic
                    }
                    if (!window.canFinish(SystemClock.elapsedRealtime())) {
                        interrupted(DptsInterruption.BUDGET_EXPIRED)
                        return@launchDiagnostic
                    }
                    rows += Zapret2GoogleAttempt(probe.method, probe.attempt,
                        response, probe.target)
                    progress.progress = rows.size
                }
                if (session != currentSession()) {
                    interrupted(DptsInterruption.SESSION_CHANGED)
                    return@launchDiagnostic
                }
                if (!window.canFinish(SystemClock.elapsedRealtime())) {
                    interrupted(DptsInterruption.BUDGET_EXPIRED)
                    return@launchDiagnostic
                }
                val report = DptsScript.report(plan, network, prepared, rows)
                // Keep the diagnostic report even for inconsistent rows,
                // but never expose training for an unbound experiment.
                lastDptsRun = DptsCompletedRun.capture(source, plan, prepared, rows, session)
                publishCompletedReport("DPpass DPTS", report, R.string.dpts_copied)
                matrixCsv = DptsCsv.render(plan, network, prepared, rows)
            } catch (_: DiagnosticIncomplete) {
                ensureActive()
                interrupted(if (session != currentSession()) DptsInterruption.SESSION_CHANGED
                    else DptsInterruption.EXECUTION_ERROR)
            } catch (cancelled: CancellationException) {
                // A hidden screen or automatic session-loss cancellation
                // must not overwrite clipboard or publish late results.
                if (manualStopRequested && session == currentSession() &&
                    source == dptsEditor.text.toString()) {
                    interrupted(DptsInterruption.USER_STOP)
                } else {
                    invalidateDptsRun()
                    statusText.text = context.getString(R.string.zapret2_autotest_cancelled)
                }
                throw cancelled
            }
        }
    }

    private fun showIncompleteDpts() {
        invalidateDptsRun()
        statusText.text = context.getString(R.string.dpts_stopped)
        resultText.text = context.getString(R.string.dpts_incomplete_report)
        resultText.visibility = View.VISIBLE
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
