package com.dpsmpx.dppass.app.ui

import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.DeviceLog
import com.dpsmpx.dppass.app.TunnelStatus
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * «Журнал» (D-26): журнал на телефоне — включить, выключить,
 * скопировать; локальный отчёт DPpass. Наружу ничего не уходит, кроме
 * буфера обмена по действию пользователя (D-12).
 */
class LogScreen(host: Host) : SubScreen(host, R.string.tab_log) {
    private val report = Ui.text(context, R.style.Text_DPpass_Mono).apply { setTextIsSelectable(true) }
    private lateinit var toggle: Ui.ListRow

    override fun content(): View = Ui.column(context, 12).apply {
        addView(
            Ui.listCard(context).apply {
                toggle = Ui.switchRow(
                    context,
                    R.drawable.ic_log,
                    context.getString(R.string.log_switch),
                    context.getString(R.string.log_note),
                    DeviceLog.enabled(context),
                ) { on ->
                    if (on != DeviceLog.enabled(context)) DeviceLog.setEnabled(context, on)
                }
                addView(toggle, Ui.matchWidth())
                addView(Ui.divider(context))
                addView(Ui.ListRow(context, R.drawable.ic_copy, context.getString(R.string.copy_log)).onClick { copy() }, Ui.matchWidth())
            },
            Ui.matchWidth(),
        )
        addView(Ui.section(context, context.getString(R.string.report_title)))
        addView(
            Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.report_note)).apply {
                setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
            },
        )
        addView(Ui.card(context).apply { addView(report, Ui.matchWidth()) }, Ui.matchWidth())
    }

    override fun render(status: TunnelStatus) = Unit

    override fun onShown() {
        refreshReport()
    }

    /** Отчёт собирается по запросу: он длинный и читает журнал целиком. */
    private fun refreshReport() {
        val core = host.graph?.core ?: return
        host.scope.launch {
            report.text = withContext(Dispatchers.Default) { core.report().render() }
        }
    }

    private fun copy() {
        DeviceLog.copyToClipboard(context, "button") { chars ->
            context.runOnUiThread {
                host.toast(
                    if (chars != null) context.resources.getQuantityString(R.plurals.log_copied, chars, chars) else context.getString(R.string.log_copy_failed),
                )
            }
        }
    }
}
