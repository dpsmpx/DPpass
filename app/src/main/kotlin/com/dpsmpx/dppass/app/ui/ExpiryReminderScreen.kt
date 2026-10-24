package com.dpsmpx.dppass.app.ui

import android.app.AlertDialog
import android.app.NotificationManager
import android.app.TimePickerDialog
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import android.text.InputType
import android.view.View
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ExpiryAlarms
import com.dpsmpx.dppass.app.TunnelState
import com.dpsmpx.dppass.app.TunnelStatus
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.subscriptions.ExpiryReminderSettings
import com.dpsmpx.dppass.subscriptions.ExpiryReminderSettings.Way
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.time.LocalTime
import java.time.format.DateTimeFormatter

/**
 * «Конец подписки» (D-76): напоминание по сроку, который сообщил
 * поставщик. Одна настройка на все подписки: способ (уведомление или
 * будильник со звуком), пороги — за сколько дней, время суток. Чего не
 * хватает, чтобы напоминание прозвучало (уведомления, точный будильник), —
 * здесь же, с переходом в настройки Android.
 */
class ExpiryReminderScreen(host: Host) : SubScreen(host, R.string.expiry_settings_title) {
    private val body = Ui.column(context, 12)

    override fun content(): View = body

    override fun onShown() = render(TunnelState.status.value)

    override fun render(status: TunnelStatus) {
        val core = host.graph?.core ?: return
        val s = host.prefs.expiryReminders
        body.removeAllViews()
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.switchRow(
                        context,
                        R.drawable.ic_bell,
                        context.getString(R.string.expiry_enable),
                        context.getString(R.string.expiry_enable_note),
                        s.enabled,
                    ) {
                        if (it) host.askNotifications()
                        set(s.copy(enabled = it))
                    },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        if (!s.enabled) return

        body.addView(caption(nextText(core)))
        problems(s).forEach { body.addView(it, Ui.matchWidth()) }

        // ---- как ----
        body.addView(Ui.section(context, context.getString(R.string.expiry_way)))
        body.addView(
            Ui.listCard(context).apply {
                addView(
                    Ui.radioRow(
                        context,
                        context.getString(R.string.expiry_way_notification),
                        context.getString(R.string.expiry_way_notification_note),
                        s.way == Way.NOTIFICATION,
                    ) {
                        set(s.copy(way = Way.NOTIFICATION))
                    },
                    Ui.matchWidth(),
                )
                addView(Ui.divider(context))
                addView(
                    Ui.radioRow(context, context.getString(R.string.expiry_way_alarm), context.getString(R.string.expiry_way_alarm_note), s.way == Way.ALARM) {
                        set(s.copy(way = Way.ALARM))
                    },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )

        // ---- когда ----
        body.addView(Ui.section(context, context.getString(R.string.expiry_when)))
        body.addView(
            Ui.listCard(context).apply {
                s.daysBefore.sortedDescending().forEachIndexed { i, d ->
                    if (i > 0) addView(Ui.divider(context))
                    val label = threshold(context, d)
                    val row = Ui.ListRow(context, R.drawable.ic_clock, label)
                    // Последний порог не убирается: без порогов напоминать не о чем.
                    if (s.daysBefore.size > 1) {
                        row.trailing(
                            Ui.iconButton(context, R.drawable.ic_delete, context.getString(R.string.expiry_remove, label), R.color.text_secondary) {
                                set(s.withoutDay(d))
                            },
                        )
                    }
                    addView(row, Ui.matchWidth())
                }
                if (s.daysBefore.size < ExpiryReminderSettings.MAX_THRESHOLDS) {
                    addView(Ui.divider(context))
                    addView(
                        Ui.ListRow(context, R.drawable.ic_add, context.getString(R.string.expiry_add))
                            .onClick { addThreshold(s) },
                        Ui.matchWidth(),
                    )
                }
                addView(Ui.divider(context))
                addView(
                    Ui.ListRow(context, R.drawable.ic_clock, context.getString(R.string.expiry_time))
                        .subtitle(time(context, s.minuteOfDay))
                        .trailing(Ui.icon(context, R.drawable.ic_chevron, R.color.text_secondary))
                        .onClick { pickTime(s) },
                    Ui.matchWidth(),
                )
            },
            Ui.matchWidth(),
        )
        body.addView(caption(context.getString(R.string.expiry_note)))
    }

    /** Ближайшее напоминание — или почему его нет. */
    private fun nextText(core: DPpassCore): String {
        val next = ExpiryAlarms.next(context, core)
        return when {
            next != null -> context.getString(R.string.expiry_next, dateTime(next.atMillis), next.name)
            !ExpiryAlarms.anyWithDate(core) -> context.getString(R.string.expiry_next_no_date)
            else -> context.getString(R.string.expiry_next_none)
        }
    }

    /** Что помешает напоминанию: уведомления выключены, нет точного будильника. */
    private fun problems(s: ExpiryReminderSettings): List<View> = buildList {
        val nm = context.getSystemService(NotificationManager::class.java)
        if (nm != null && !nm.areNotificationsEnabled()) {
            add(
                warning(R.string.expiry_problem_notifications) {
                    open(Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE, context.packageName))
                },
            )
        }
        // Нет точного будильника — только с Android 12: тогда есть и экран разрешения.
        if (s.way == Way.ALARM && !ExpiryAlarms.exactAllowed(context)) {
            add(
                warning(R.string.expiry_problem_exact) {
                    open(Intent(Settings.ACTION_REQUEST_SCHEDULE_EXACT_ALARM, Uri.parse("package:" + context.packageName)))
                },
            )
        }
    }

    private fun warning(text: Int, action: () -> Unit): View = Ui.listCard(context).apply {
        addView(
            Ui.ListRow(context, R.drawable.ic_info, context.getString(text))
                .trailing(Ui.icon(context, R.drawable.ic_open, R.color.text_secondary))
                .onClick(action)
                .apply { title.setTextColor(context.getColor(R.color.warning)) },
            Ui.matchWidth(),
        )
    }

    /**
     * Новый порог: готовые «за 5 дней», «за день», «в день окончания» —
     * и поле числа дней (0…60). Неверное число — ошибка у поля, окно не
     * закрывается.
     */
    private fun addThreshold(s: ExpiryReminderSettings) {
        val field = Ui.field(context, R.string.expiry_days_hint, InputType.TYPE_CLASS_NUMBER)
        val form = Ui.column(context, 8).apply {
            val p = Ui.dp(context, 24)
            setPadding(p, Ui.dp(context, 8), p, 0)
        }
        val dialog = AlertDialog.Builder(context)
            .setTitle(R.string.expiry_add)
            .setView(form)
            .setPositiveButton(R.string.expiry_add_button, null)
            .setNegativeButton(android.R.string.cancel, null)
            .create()
        PRESETS.filter { it !in s.daysBefore }.forEach { d ->
            form.addView(
                Ui.button(context, R.string.expiry_add_button, Ui.Style.TONAL).apply {
                    text = threshold(context, d)
                    setOnClickListener {
                        dialog.dismiss()
                        s.withDay(d)?.let(::set)
                    }
                },
                Ui.matchWidth(),
            )
        }
        form.addView(field, Ui.matchWidth())
        Ui.secure(dialog)
        dialog.show()
        dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
            val next = field.text.toString().trim().toIntOrNull()?.let(s::withDay)
            if (next == null) {
                field.error = context.getString(R.string.expiry_days_error, ExpiryReminderSettings.MAX_DAYS)
                return@setOnClickListener
            }
            dialog.dismiss()
            set(next)
        }
    }

    private fun pickTime(s: ExpiryReminderSettings) {
        val dialog = TimePickerDialog(
            context,
            { _, hour, minute -> set(s.copy(minuteOfDay = hour * 60 + minute)) },
            s.minuteOfDay / 60,
            s.minuteOfDay % 60,
            android.text.format.DateFormat.is24HourFormat(context),
        )
        Ui.secure(dialog)
        dialog.show()
    }

    /** Сохранить и пересчитать (D-76); туннель не затрагивается. */
    private fun set(next: ExpiryReminderSettings) {
        val core = host.graph?.core ?: return
        if (next == host.prefs.expiryReminders) return
        val app = context.applicationContext
        host.scope.launch {
            withContext(Dispatchers.IO) { ExpiryAlarms.change(app, core, next) }
            host.changed()
        }
    }

    private fun caption(text: String): View = Ui.text(context, R.style.Text_DPpass_Caption, text).apply {
        setPadding(Ui.dp(context, 4), 0, Ui.dp(context, 4), 0)
    }

    private fun open(intent: Intent) {
        try {
            context.startActivity(intent)
        } catch (e: ActivityNotFoundException) {
            host.toast(context.getString(R.string.no_system_screen))
        }
    }

    companion object {
        /** Готовые пороги: за 5 дней, за день, в день окончания. */
        private val PRESETS = listOf(5, 1, 0)

        /** «За 5 дней», «за день», «в день окончания». */
        fun threshold(context: Context, days: Int): String = when (days) {
            0 -> context.getString(R.string.expiry_day_of)
            1 -> context.getString(R.string.expiry_day_before)
            else -> context.getString(R.string.expiry_days_before, context.resources.getQuantityString(R.plurals.days, days, days))
        }

        fun time(context: Context, minuteOfDay: Int): String {
            val pattern = if (android.text.format.DateFormat.is24HourFormat(context)) "HH:mm" else "h:mm a"
            return LocalTime.of(minuteOfDay / 60, minuteOfDay % 60).format(DateTimeFormatter.ofPattern(pattern, context.resources.configuration.locales[0]))
        }

        /** Строка в «Настройках»: выключено — или способ, пороги и время. */
        fun summary(context: Context, s: ExpiryReminderSettings): String {
            if (!s.enabled) return context.getString(R.string.expiry_off)
            val way = context.getString(if (s.way == Way.ALARM) R.string.expiry_way_alarm else R.string.expiry_way_notification)
            val locale = context.resources.configuration.locales[0]
            // Внутри строки — со строчной: «за 5 дней, за день, в день окончания».
            val days = s.daysBefore.sortedDescending().joinToString(", ") { d -> threshold(context, d).replaceFirstChar { it.lowercase(locale) } }
            return context.getString(R.string.expiry_summary, way, days, time(context, s.minuteOfDay))
        }
    }
}
