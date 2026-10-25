package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.text.InputType
import android.view.View
import android.widget.LinearLayout
import android.widget.NumberPicker
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.app.UsageAlerts
import com.dpsmpx.dppass.connection.UsageBytes
import com.dpsmpx.dppass.connection.UsageSettings
import com.dpsmpx.dppass.connection.UsageSummary
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.network.NetworkType

/**
 * «Трафик через сервер» (D-92): сегодня и расчётный период по сетям,
 * порог мобильной сети, день начала периода, ручной сброс. Порог только
 * предупреждает — туннель не отключается.
 */
class UsageScreen(host: Host) : SubScreen(host, R.string.usage_title) {
    private val body = Ui.column(context, 12)

    override fun content(): View = body

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        val s = core.usage.summary()
        body.removeAllViews()
        body.addView(Ui.section(context, context.getString(R.string.usage_today)))
        body.addView(networks(s.today), Ui.matchWidth())
        val from = UsageAlerts.date(context, s.periodStart)
        val to = UsageAlerts.date(context, s.periodEnd.minusDays(1))
        body.addView(Ui.section(context, context.getString(R.string.usage_period, from, to)))
        body.addView(networks(s.period), Ui.matchWidth())
        limit(s)?.let { body.addView(it, Ui.matchWidth()) }
        s.resetAtMillis?.let { body.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.usage_reset_at, dateTime(it)))) }

        body.addView(Ui.section(context, context.getString(R.string.usage_settings)))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.ListRow(context, R.drawable.ic_clock, context.getString(R.string.usage_start_day))
                        .subtitle(
                            context.getString(R.string.usage_start_day_value, s.settings.periodStartDay) + "\n" +
                                context.getString(R.string.usage_start_day_note),
                        )
                        .onClick { pickStartDay(s.settings) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_bell, context.getString(R.string.usage_limit))
                        .subtitle(
                            s.settings.mobileLimitBytes?.let { context.getString(R.string.usage_limit_value, bytes(it)) }
                                ?: context.getString(R.string.usage_limit_off),
                        )
                        .onClick { editLimit(s.settings) },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_refresh, context.getString(R.string.usage_reset))
                        .subtitle(context.getString(R.string.usage_reset_note))
                        .onClick { confirmReset() },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        body.addView(Ui.text(context, R.style.Text_DPpass_Caption, context.getString(R.string.usage_note)))
    }

    /** Мобильная и Wi-Fi — всегда (ноль — тоже ответ); прочие сети — если в них что-то было. */
    private fun networks(by: Map<NetworkType, UsageBytes>): LinearLayout = Ui.listCard(context).apply {
        val other = listOf(NetworkType.ETHERNET, NetworkType.OTHER).mapNotNull(by::get).fold(UsageBytes.ZERO, UsageBytes::plus)
        val rows = listOf(
            R.string.usage_mobile to (by[NetworkType.MOBILE] ?: UsageBytes.ZERO),
            R.string.usage_wifi to (by[NetworkType.WIFI] ?: UsageBytes.ZERO),
        ) + if (other.total > 0) listOf(R.string.usage_other to other) else emptyList()
        rows.forEachIndexed { i, (title, b) ->
            if (i > 0) addView(Ui.divider(context))
            val text = context.getString(R.string.usage_bytes, bytes(b.total), bytes(b.down), bytes(b.up))
            addView(Ui.ListRow(context, null, context.getString(title)).subtitle(text), Ui.matchWidth())
        }
    }

    private fun limit(s: UsageSummary): View? {
        val limit = s.settings.mobileLimitBytes ?: return null
        val fraction = s.mobileLimitFraction ?: return null
        return Ui.card(context, 8).apply {
            addView(
                Ui.text(context, R.style.Text_DPpass_Secondary, context.getString(R.string.usage_limit_of, bytes(s.mobilePeriodBytes), bytes(limit))).apply {
                    if (fraction >= 1.0) setTextColor(context.getColor(R.color.warning))
                },
            )
            addView(Ui.Meter(context).apply { this.fraction = fraction.toFloat() }, Ui.matchWidth())
        }
    }

    private fun pickStartDay(current: UsageSettings) {
        val picker = NumberPicker(context).apply {
            minValue = UsageSettings.DAYS.first
            maxValue = UsageSettings.DAYS.last
            value = current.periodStartDay
            wrapSelectorWheel = false
        }
        Ui.secure(
            AlertDialog.Builder(context)
                .setTitle(R.string.usage_start_day)
                .setView(picker)
                .setPositiveButton(R.string.action_save) { _, _ -> save(current.copy(periodStartDay = picker.value)) }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    private fun editLimit(current: UsageSettings) {
        val field = Ui.field(context, R.string.usage_limit_hint, InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL).apply {
            current.mobileLimitBytes?.let { setText(UsageSettings.gigabytes(it)) }
        }
        val form = Ui.column(context, 8).apply {
            val p = Ui.dp(context, 24)
            setPadding(p, Ui.dp(context, 8), p, 0)
            addView(field, Ui.matchWidth())
        }
        Ui.secure(
            AlertDialog.Builder(context)
                .setTitle(R.string.usage_limit)
                .setView(form)
                .setPositiveButton(R.string.action_save) { _, _ ->
                    val bytes = UsageSettings.parseGigabytes(field.text.toString())
                    if (bytes == null) host.toast(context.getString(R.string.usage_limit_bad)) else save(current.copy(mobileLimitBytes = bytes))
                }
                .setNeutralButton(R.string.usage_limit_none) { _, _ -> save(current.copy(mobileLimitBytes = null)) }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    private fun confirmReset() {
        Ui.secure(
            AlertDialog.Builder(context)
                .setMessage(R.string.usage_reset_confirm)
                .setPositiveButton(android.R.string.ok) { _, _ -> edit { host.graph?.core?.usage?.reset() } }
                .setNegativeButton(android.R.string.cancel, null)
                .show(),
        )
    }

    private fun save(s: UsageSettings) = edit { host.graph?.core?.usage?.setSettings(s) }

    /** Правка сохраняется сразу; отказ — с причиной. */
    private fun edit(change: () -> Outcome<*>?) {
        when (val r = change()) {
            is Outcome.Failure -> host.problem(context.getString(Ui.kind(r.errors.first().kind)), r.errors.first())
            else -> Unit
        }
        host.changed()
    }
}
