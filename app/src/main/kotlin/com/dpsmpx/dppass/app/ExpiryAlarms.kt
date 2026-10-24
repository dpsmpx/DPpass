package com.dpsmpx.dppass.app

import android.app.AlarmManager
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.graphics.drawable.Icon
import android.media.AudioAttributes
import android.media.RingtoneManager
import android.os.Build
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Host
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.subscriptions.ExpiryReminder
import com.dpsmpx.dppass.subscriptions.ExpiryReminderSettings
import com.dpsmpx.dppass.subscriptions.ExpiryReminders
import com.dpsmpx.dppass.subscriptions.Subscription
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import java.text.DateFormat
import java.time.ZoneId
import java.util.Date

/**
 * Напоминание о конце подписки на Android (D-76). Когда звучать, решает
 * ядро ([ExpiryReminders]); здесь — будильник Android на ближайшее
 * напоминание, уведомление и кнопки будильника.
 *
 * Будильник Android ставится заново ([sync]) при каждом изменении,
 * которое могло сдвинуть план: подписки и сроки, настройка, срабатывание,
 * загрузка телефона ([ExpiryBootReceiver]). Пропущенное (телефон был
 * выключен) приходит при первой возможности — одно, не залпом.
 */
internal object ExpiryAlarms {
    private const val CHANNEL = "expiry"
    private const val CHANNEL_ALARM = "expiry_alarm"

    // Уведомления: 1 — туннель, 2 — смена сервера; напоминания — свои у каждой подписки.
    private const val NOTIFICATION_BASE = 100
    private const val NOTIFICATIONS = 900

    // Коды запросов: у туннеля 0 и 1, у смены сервера — 10…12.
    private const val REQUEST_NEXT = 20
    private const val REQUEST_OPEN = 21

    /** Без точного будильника — окно в час: в Doze — при пробуждении телефона, уведомлению этого хватает. */
    private const val WINDOW_MILLIS = 60 * 60_000L

    const val ACTION_NEXT: String = "com.dpsmpx.dppass.action.EXPIRY_NEXT"
    const val ACTION_SNOOZE: String = "com.dpsmpx.dppass.action.EXPIRY_SNOOZE"
    const val ACTION_SNOOZED: String = "com.dpsmpx.dppass.action.EXPIRY_SNOOZED"
    const val ACTION_DISMISS: String = "com.dpsmpx.dppass.action.EXPIRY_DISMISS"
    private const val EXTRA_KEY = "key"

    private val lock = Any()

    /** Что видел последний [sync] этого процесса: подписки со сроками и настройка. */
    private var synced: Any? = null

    /** Подписки и сроки изменились с последнего [sync] — пересчитать; иначе ничего (зовётся при каждой перерисовке). */
    fun syncIfChanged(context: Context, core: DPpassCore) {
        val subs = subscriptions(core) ?: return
        if (input(subs, AppPrefs(context).expiryReminders) != synchronized(lock) { synced }) sync(context, core)
    }

    /**
     * Показать наступившее и поставить будильник Android на ближайшее.
     * Подписки не прочитать (хранилище недоступно, D-19) — ничего не
     * трогать: иначе отметки «уже напомнили» стёрлись бы.
     */
    fun sync(context: Context, core: DPpassCore) {
        synchronized(lock) { syncLocked(context, core) }
    }

    private fun syncLocked(context: Context, core: DPpassCore) {
        val subs = subscriptions(core) ?: return
        val prefs = AppPrefs(context)
        val settings = prefs.expiryReminders
        val now = Clock.SYSTEM.nowMillis()
        val plan = ExpiryReminders.planned(subs, settings, ZoneId.systemDefault())
        val due = ExpiryReminders.due(plan, now, prefs.expiryDone)
        due.show.forEach { show(context, core, it.reminder, alarm = settings.way == ExpiryReminderSettings.Way.ALARM && !it.late) }
        prefs.expiryDone = due.done
        val next = ExpiryReminders.next(plan, now, due.done)
        val pi = PendingIntent.getBroadcast(context, REQUEST_NEXT, Intent(context, ExpiryReceiver::class.java).setAction(ACTION_NEXT), FLAGS)
        val am = context.getSystemService(AlarmManager::class.java)
        if (next == null) am?.cancel(pi) else am?.let { wake(context, it, settings.way == ExpiryReminderSettings.Way.ALARM, next.atMillis, pi) }
        synced = input(subs, settings)
    }

    /**
     * Настройку сменил пользователь: сохранить, отметить уже наступившие
     * пороги (сохранение не будит будильником, [ExpiryReminders.afterChange])
     * и пересчитать. Включено — приёмник загрузки включён: будильники
     * Android перезагрузку не переживают; выключено — DPpass при загрузке
     * не запускается (D-40).
     */
    fun change(context: Context, core: DPpassCore, next: ExpiryReminderSettings) {
        synchronized(lock) { changeLocked(context, core, next) }
    }

    private fun changeLocked(context: Context, core: DPpassCore, next: ExpiryReminderSettings) {
        val prefs = AppPrefs(context)
        prefs.expiryReminders = next
        context.packageManager.setComponentEnabledSetting(
            ComponentName(context, ExpiryBootReceiver::class.java),
            if (next.enabled) PackageManager.COMPONENT_ENABLED_STATE_ENABLED else PackageManager.COMPONENT_ENABLED_STATE_DISABLED,
            PackageManager.DONT_KILL_APP,
        )
        core.log.info(
            "expiry_reminders_set",
            "on" to next.enabled,
            "way" to Safe(next.way.wire),
            "days" to Safe(ExpiryReminderSettings.formatDays(next.daysBefore)),
            "minute" to next.minuteOfDay,
        )
        // Подписки не прочитать — выбор сохранён, отметки и будильник — при следующем чтении.
        val subs = subscriptions(core) ?: return
        val plan = ExpiryReminders.planned(subs, next, ZoneId.systemDefault())
        prefs.expiryDone = ExpiryReminders.afterChange(plan, Clock.SYSTEM.nowMillis(), prefs.expiryDone)
        syncLocked(context, core)
    }

    /** Ближайшее напоминание впереди — для строки в «Настройках». */
    fun next(context: Context, core: DPpassCore): ExpiryReminder? {
        val subs = subscriptions(core) ?: return null
        val prefs = AppPrefs(context)
        val plan = ExpiryReminders.planned(subs, prefs.expiryReminders, ZoneId.systemDefault())
        return ExpiryReminders.next(plan, Clock.SYSTEM.nowMillis(), prefs.expiryDone)
    }

    /** Подписки со сроками есть — есть о чём напоминать. */
    fun anyWithDate(core: DPpassCore): Boolean = subscriptions(core)?.any { ExpiryReminders.expireMillis(it) != null } == true

    /** Будильник в точное время возможен: до Android 12 — всегда, дальше — с разрешением «Будильники и напоминания». */
    fun exactAllowed(context: Context): Boolean =
        Build.VERSION.SDK_INT < Build.VERSION_CODES.S || context.getSystemService(AlarmManager::class.java)?.canScheduleExactAlarms() == true

    /** Нажатие кнопки будильника или срабатывание будильника Android. */
    fun handle(context: Context, intent: Intent) {
        val key = intent.getStringExtra(EXTRA_KEY)
        when (intent.action) {
            ACTION_DISMISS -> key?.let { cancel(context, it) }
            ACTION_SNOOZE -> key?.let { snooze(context, it) }
            ACTION_SNOOZED -> key?.let { snoozed(context, AppGraph.core(context), it) }
            else -> sync(context, AppGraph.core(context))
        }
    }

    private fun subscriptions(core: DPpassCore): List<Subscription>? = (core.subscriptions.state() as? Outcome.Success)?.value?.items

    private fun input(subs: List<Subscription>, settings: ExpiryReminderSettings): Any =
        subs.map { it.id to ExpiryReminders.expireMillis(it) } to settings

    /**
     * Будильник Android на [atMillis]. Точный ([exact], способ «будильник»)
     * — `setAlarmClock`: его не откладывает Doze, а система показывает
     * его как будильник. Без разрешения — окно в час, и «Настройки» об этом
     * говорят.
     */
    private fun wake(context: Context, am: AlarmManager, exact: Boolean, atMillis: Long, pi: PendingIntent) {
        if (exact && (Build.VERSION.SDK_INT < Build.VERSION_CODES.S || am.canScheduleExactAlarms())) {
            try {
                am.setAlarmClock(AlarmManager.AlarmClockInfo(atMillis, open(context)), pi)
                return
            } catch (e: SecurityException) {
                // Разрешение отозвали между проверкой и вызовом — как без него.
                AppGraph.core(context).log.warning("expiry_exact_denied", "error" to Safe(e.javaClass.simpleName))
            }
        }
        am.setWindow(AlarmManager.RTC_WAKEUP, atMillis, WINDOW_MILLIS, pi)
    }

    /** «Отложить» (D-76): то же напоминание будильником через 10 минут; само не повторяется. */
    private fun snooze(context: Context, key: String) {
        cancel(context, key)
        val am = context.getSystemService(AlarmManager::class.java) ?: return
        val pi = PendingIntent.getBroadcast(context, notificationId(key), action(context, ACTION_SNOOZED, key), FLAGS)
        wake(context, am, exact = true, Clock.SYSTEM.nowMillis() + ExpiryReminders.SNOOZE_MILLIS, pi)
    }

    /** Отложенное — только если оно ещё в плане: подписку не удалили и не продлили, настройку не выключили. */
    private fun snoozed(context: Context, core: DPpassCore, key: String) {
        val subs = subscriptions(core) ?: return
        val now = Clock.SYSTEM.nowMillis()
        val r = ExpiryReminders.planned(subs, AppPrefs(context).expiryReminders, ZoneId.systemDefault())
            .firstOrNull { it.key == key && now < it.expireMillis } ?: return
        show(context, core, r, alarm = true)
    }

    private fun show(context: Context, core: DPpassCore, r: ExpiryReminder, alarm: Boolean) {
        val nm = context.getSystemService(NotificationManager::class.java) ?: return
        channels(context, nm)
        val channel = if (alarm) CHANNEL_ALARM else CHANNEL
        if (!nm.areNotificationsEnabled() || nm.getNotificationChannel(channel)?.importance == NotificationManager.IMPORTANCE_NONE) {
            // Уведомления выключены — «Настройки» об этом говорят; здесь только запись в журнал.
            core.log.warning("expiry_reminder_blocked", "days" to r.daysBefore)
            return
        }
        val title = context.getString(R.string.expiry_title)
        val text = text(context, r)
        // На заблокированном экране — без имени подписки (T9): оно часто называет поставщика.
        val public = Notification.Builder(context, channel)
            .setContentTitle(title)
            .setContentText(context.getString(R.string.expiry_public))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
        val n = Notification.Builder(context, channel)
            .setContentTitle(title)
            .setContentText(text)
            .setStyle(Notification.BigTextStyle().bigText(text))
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentIntent(open(context))
            .setAutoCancel(true)
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setCategory(if (alarm) Notification.CATEGORY_ALARM else Notification.CATEGORY_REMINDER)
        if (alarm) {
            // Кнопки будильника ничего не раскрывают — они есть и на заблокированном экране.
            val actions = listOf(
                button(context, R.drawable.ic_check, R.string.expiry_dismiss, ACTION_DISMISS, r.key),
                button(context, R.drawable.ic_clock, R.string.expiry_snooze, ACTION_SNOOZE, r.key),
            )
            actions.forEach { a ->
                n.addAction(a)
                public.addAction(a)
            }
        }
        nm.notify(notificationId(r.key), n.setPublicVersion(public.build()).build())
        core.log.info("expiry_reminder", "days" to r.daysBefore, "alarm" to alarm)
    }

    /** «Подписка «X» закончится сегодня в 15:00 / завтра в 15:00 / через 5 дней — 30 окт.». */
    private fun text(context: Context, r: ExpiryReminder): String {
        val locale = context.resources.configuration.locales[0]
        val left = ExpiryReminders.daysLeft(r.expireMillis, Clock.SYSTEM.nowMillis(), ZoneId.systemDefault())
        val time = android.text.format.DateFormat.getTimeFormat(context).format(Date(r.expireMillis))
        return when {
            left <= 0L -> context.getString(R.string.expiry_text_today, r.name, time)
            left == 1L -> context.getString(R.string.expiry_text_tomorrow, r.name, time)
            else -> context.getString(
                R.string.expiry_text_days,
                r.name,
                context.resources.getQuantityString(R.plurals.days, left.toInt(), left.toInt()),
                DateFormat.getDateInstance(DateFormat.MEDIUM, locale).format(Date(r.expireMillis)),
            )
        }
    }

    /**
     * Каналы: обычный — и будильник со звуком будильника телефона (громкость
     * будильника, `USAGE_ALARM`). Звук канала пользователь меняет в
     * настройках Android.
     */
    private fun channels(context: Context, nm: NotificationManager) {
        nm.createNotificationChannel(NotificationChannel(CHANNEL, context.getString(R.string.expiry_channel), NotificationManager.IMPORTANCE_DEFAULT))
        nm.createNotificationChannel(
            NotificationChannel(CHANNEL_ALARM, context.getString(R.string.expiry_alarm_channel), NotificationManager.IMPORTANCE_HIGH).apply {
                setSound(
                    RingtoneManager.getDefaultUri(RingtoneManager.TYPE_ALARM),
                    AudioAttributes.Builder()
                        .setUsage(AudioAttributes.USAGE_ALARM)
                        .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION)
                        .build(),
                )
                enableVibration(true)
            },
        )
    }

    private fun cancel(context: Context, key: String) {
        context.getSystemService(NotificationManager::class.java)?.cancel(notificationId(key))
    }

    /** Своё уведомление у каждой подписки: по id подписки из [ExpiryReminder.key]. */
    private fun notificationId(key: String): Int {
        val subscription = key.substringBeforeLast(':').substringBeforeLast(':')
        return NOTIFICATION_BASE + Math.floorMod(subscription.hashCode(), NOTIFICATIONS)
    }

    private fun open(context: Context): PendingIntent = PendingIntent.getActivity(
        context,
        REQUEST_OPEN,
        Intent(context, MainActivity::class.java)
            .addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP)
            .putExtra(Host.EXTRA_TAB, Host.TAB_SUBSCRIPTIONS),
        FLAGS,
    )

    private fun action(context: Context, action: String, key: String): Intent =
        Intent(context, ExpiryReceiver::class.java).setAction(action).putExtra(EXTRA_KEY, key)

    private fun button(context: Context, icon: Int, label: Int, action: String, key: String): Notification.Action =
        Notification.Action.Builder(
            Icon.createWithResource(context, icon),
            context.getString(label),
            PendingIntent.getBroadcast(context, notificationId(key), action(context, action, key), FLAGS),
        ).build()

    private const val FLAGS = PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
}

/**
 * Будильник Android и кнопки напоминания (D-76). Не экспортирован: его
 * зовут только свои `PendingIntent`.
 */
class ExpiryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        val pending = goAsync()
        val app = context.applicationContext
        AppGraph.scope.launch(Dispatchers.IO) {
            try {
                ExpiryAlarms.handle(app, intent)
            } finally {
                pending.finish()
            }
        }
    }
}

/**
 * Загрузка телефона, обновление DPpass, выданное разрешение на точный
 * будильник (D-76): будильник Android — заново. Включён, только пока
 * напоминание включено ([ExpiryAlarms.change]); иначе DPpass при загрузке
 * не запускается (D-40). Не экспортирован: эти события шлёт система.
 */
class ExpiryBootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action !in ACTIONS) return
        val pending = goAsync()
        val app = context.applicationContext
        AppGraph.scope.launch(Dispatchers.IO) {
            try {
                ExpiryAlarms.sync(app, AppGraph.core(app))
            } finally {
                pending.finish()
            }
        }
    }

    private companion object {
        val ACTIONS = setOf(
            Intent.ACTION_BOOT_COMPLETED,
            Intent.ACTION_MY_PACKAGE_REPLACED,
            // AlarmManager.ACTION_SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED — с Android 12; строкой, как в манифесте.
            "android.app.action.SCHEDULE_EXACT_ALARM_PERMISSION_STATE_CHANGED",
        )
    }
}
