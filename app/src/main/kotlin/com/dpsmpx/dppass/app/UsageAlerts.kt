package com.dpsmpx.dppass.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Formats
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.UsageAlert
import java.text.DateFormat
import java.time.LocalDate
import java.time.ZoneId
import java.util.Date

/**
 * Порог мобильного трафика пройден (D-92): одно уведомление за период.
 * Туннель не отключается — это только предупреждение; порог и счёт — в
 * «Учёте трафика». На заблокированном экране — без чисел.
 */
object UsageAlerts {
    private const val CHANNEL = "usage"
    private const val NOTIFICATION_ID = 3
    private const val REQUEST_OPEN = 30

    fun show(context: Context, core: DPpassCore, alert: UsageAlert) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.usage_channel), NotificationManager.IMPORTANCE_DEFAULT))
        if (!nm.areNotificationsEnabled() || nm.getNotificationChannel(CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE) {
            core.log.warning("usage_alert_blocked")
            return
        }
        val text = text(context, alert)
        val title = context.getString(R.string.usage_alert_title)
        val public = Notification.Builder(context, CHANNEL)
            .setContentTitle(title)
            .setContentText(context.getString(R.string.usage_alert_public))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
        val n = Notification.Builder(context, CHANNEL)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentIntent(open(context))
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setCategory(Notification.CATEGORY_STATUS)
            .setPublicVersion(public.build())
            .build()
        nm.notify(NOTIFICATION_ID, n)
        core.log.info("usage_alert", "used" to alert.usedBytes, "limit" to alert.limitBytes)
    }

    fun text(context: Context, alert: UsageAlert): String {
        val locale = context.resources.configuration.locales[0]
        val units = context.resources.getStringArray(R.array.units_bytes).toList()
        return context.getString(
            R.string.usage_alert_text,
            date(context, alert.periodStart),
            Formats.bytes(alert.usedBytes, units, locale),
            Formats.bytes(alert.limitBytes, units, locale),
        )
    }

    /** Дата начала суток [day] в часовом поясе устройства — как на экранах. */
    fun date(context: Context, day: LocalDate): String =
        DateFormat.getDateInstance(DateFormat.MEDIUM, context.resources.configuration.locales[0])
            .format(Date(day.atStartOfDay(ZoneId.systemDefault()).toInstant().toEpochMilli()))

    private fun open(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        REQUEST_OPEN,
        Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(Host.EXTRA_TAB, Host.TAB_CONNECT),
        PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )
}
