package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DptsDiagnosticJob
import com.dpsmpx.dppass.app.RootCapabilitySurvey
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.withContext

/** No ROOT request on opening this screen; explicit confirmation only. */
internal class RootCapabilityScreen(host: Host) : SubScreen(host, R.string.root_capability_title) {
    private val run = Ui.button(context, R.string.root_capability_run, Ui.Style.PRIMARY, R.drawable.ic_shield)
    private val result = Ui.text(context, R.style.Text_DPpass_Body).apply { setTextIsSelectable(true) }
    private val job = DptsDiagnosticJob(host.scope, failed = {
        result.setText(R.string.root_capability_unknown)
    }) {
        refresh()
    }

    override fun content(): View = Ui.column(context, 12).apply {
        addView(Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.root_capability_intro)), Ui.matchWidth())
        addView(run.apply { setOnClickListener { confirm() } }, Ui.matchWidth())
        addView(result, Ui.matchWidth())
        addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.root_capability_limit)), Ui.matchWidth())
    }

    override fun onShown() = refresh()
    override fun onHidden() { job.cancel() }
    override fun render(status: TunnelStatus) {
        if (status != TunnelStatus.Idle && job.cancellable) job.cancel()
        refresh()
    }

    private fun refresh() {
        run.isEnabled = !job.busy && TunnelState.status.value == TunnelStatus.Idle
    }

    private fun confirm() {
        if (job.busy || TunnelState.status.value != TunnelStatus.Idle) return
        AlertDialog.Builder(context).setTitle(R.string.root_capability_title)
            .setMessage(R.string.root_capability_confirm)
            .setNegativeButton(android.R.string.cancel, null)
            .setPositiveButton(android.R.string.ok) { _, _ -> start() }.show()
    }

    private fun start() {
        val before = TunnelState.snapshot()
        if (job.busy || before.status != TunnelStatus.Idle) return
        result.setText(R.string.root_capability_running)
        job.start {
            val report = withContext(Dispatchers.IO) { RootCapabilitySurvey.run() }
            ensureActive()
            if (TunnelState.snapshot() != before) {
                result.setText(R.string.root_capability_changed)
            } else if (report == null) {
                result.setText(R.string.root_capability_unknown)
            } else {
                val rows = listOf(
                    R.string.root_capability_root to true,
                    R.string.root_capability_admin to report.netAdmin,
                    R.string.root_capability_raw to report.netRaw,
                    R.string.root_capability_v4nat to report.ipv4Nat,
                    R.string.root_capability_v4mangle to report.ipv4Mangle,
                    R.string.root_capability_v6nat to report.ipv6Nat,
                    R.string.root_capability_v6mangle to report.ipv6Mangle,
                )
                result.text = rows.joinToString("\n") { (label, available) ->
                    context.getString(label) + ": " + context.getString(
                        if (available) R.string.root_capability_yes else R.string.root_capability_no)
                }
            }
        }
    }
}
