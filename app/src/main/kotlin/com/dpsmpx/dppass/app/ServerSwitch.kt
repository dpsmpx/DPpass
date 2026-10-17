package com.dpsmpx.dppass.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Avatar
import com.dpsmpx.dppass.app.ui.Ui
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.diagnostics.Diagnostic

/**
 * Сбой выбранного сервера (D-58): вопрос «перейти?» и сообщение о
 * замене — уведомлением своего канала («Смена сервера») и карточкой
 * экрана «Подключение» ([TunnelState.offer]): без разрешения на
 * уведомления вопрос не теряется.
 *
 * На заблокированном экране — без имён серверов и без кнопок (T9): имя
 * часто называет страну и поставщика, а выбор — после разблокировки.
 */
internal object ServerSwitch {
    private const val CHANNEL = "server_switch"
    private const val NOTIFICATION_ID = 2

    /** Спросить, перейти ли с [Degradation.Ask.from] на [Degradation.Ask.to]; повтор не звучит заново. */
    fun ask(context: Context, d: Degradation.Ask): Boolean {
        val from = Avatar.stripFlag(d.from.name)
        val to = Avatar.stripFlag(d.to.name)
        TunnelState.offer(ServerOffer(d.from.id, from, d.to.id, to, d.reason))
        val text = context.getString(R.string.switch_ask_text, from, kind(context, d.reason), to)
        val switch = PendingIntent.getForegroundService(
            context,
            REQUEST_SWITCH,
            DPpassVpnService.switchIntent(context, d.to.id),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val keep = PendingIntent.getService(
            context,
            REQUEST_KEEP,
            DPpassVpnService.keepIntent(context, d.from.id),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val n = builder(context, R.string.switch_title, text, d.reason)
            .addAction(Notification.Action.Builder(Icon.createWithResource(context, R.drawable.ic_bolt), context.getString(R.string.action_switch), switch).build())
            .addAction(Notification.Action.Builder(Icon.createWithResource(context, R.drawable.ic_check), context.getString(R.string.action_keep), keep).build())
            // Смахнули — ответ «Остаться»: не спрашивать снова до остановки туннеля.
            .setDeleteIntent(keep)
            .build()
        return post(context, n)
    }

    /** Автопереключение (D-58): сообщить, с какого сервера на какой и почему. */
    fun switched(context: Context, d: Degradation.Switch): Boolean {
        TunnelState.offer(null)
        val text = context.getString(R.string.switch_done_text, Avatar.stripFlag(d.from.name), kind(context, d.reason), Avatar.stripFlag(d.to.name))
        return post(context, builder(context, R.string.switch_done_title, text, d.reason).setAutoCancel(true).build())
    }

    /** Вопрос снят: ответ получен, туннель остановлен или подключён другой сервер. */
    fun clear(context: Context) {
        TunnelState.offer(null)
        context.getSystemService(NotificationManager::class.java)?.cancel(NOTIFICATION_ID)
    }

    private fun builder(context: Context, title: Int, text: String, reason: Diagnostic): Notification.Builder {
        val open = PendingIntent.getActivity(
            context,
            REQUEST_OPEN,
            Intent(context, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val public = Notification.Builder(context, CHANNEL)
            .setContentTitle(context.getString(title))
            .setContentText(context.getString(R.string.switch_public))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .build()
        return Notification.Builder(context, CHANNEL)
            .setContentTitle(context.getString(title))
            .setContentText(text)
            // Полная причина — ниже, в развёрнутом виде: в ней нет адресов (D-32, `XrayHealth`).
            .setStyle(Notification.BigTextStyle().bigText(text + "\n" + reason.message))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentIntent(open)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_STATUS)
    }

    /** Ложь — уведомления выключены: вопрос остаётся только на экране. */
    private fun post(context: Context, n: Notification): Boolean {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return false
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.switch_channel), NotificationManager.IMPORTANCE_DEFAULT))
        if (!nm.areNotificationsEnabled() || nm.getNotificationChannel(CHANNEL)?.importance == NotificationManager.IMPORTANCE_NONE) return false
        nm.notify(NOTIFICATION_ID, n)
        return true
    }

    /** Категория отказа строчными — внутри фразы: «сервер недоступен». */
    private fun kind(context: Context, reason: Diagnostic): String {
        val locale = context.resources.configuration.locales[0]
        return context.getString(Ui.kind(reason.kind)).replaceFirstChar { it.lowercase(locale) }
    }

    // Коды запросов — свои, чтобы не совпасть с PendingIntent уведомления туннеля (0 и 1).
    private const val REQUEST_OPEN = 10
    private const val REQUEST_SWITCH = 11
    private const val REQUEST_KEEP = 12
}
