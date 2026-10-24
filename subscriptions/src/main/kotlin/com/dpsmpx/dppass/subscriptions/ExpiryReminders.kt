package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.core.SubscriptionId
import java.time.Instant
import java.time.LocalTime
import java.time.ZoneId
import java.time.temporal.ChronoUnit

/**
 * Напоминание о конце подписки (D-76): выбор пользователя на этом
 * телефоне, одна настройка на все подписки. Срок — `expire` поставщика
 * (`subscription-userinfo`); управляющий заголовок поставщика
 * `notification-subs-expire` настройку не меняет (D-11).
 */
data class ExpiryReminderSettings(
    val enabled: Boolean = false,
    val way: Way = Way.NOTIFICATION,
    /** За сколько календарных дней до дня окончания; 0 — в сам день. */
    val daysBefore: Set<Int> = DEFAULT_DAYS,
    /** Время суток по часам телефона, минуты от полуночи. */
    val minuteOfDay: Int = DEFAULT_MINUTE,
) {
    /** Обычное уведомление — или будильник со звуком в точное время. */
    enum class Way(val wire: String) { NOTIFICATION("notification"), ALARM("alarm") }

    /** Порог [days] добавлен; null — вне 0…[MAX_DAYS] или порогов уже [MAX_THRESHOLDS]. */
    fun withDay(days: Int): ExpiryReminderSettings? = when {
        days !in 0..MAX_DAYS -> null
        days in daysBefore -> this
        daysBefore.size >= MAX_THRESHOLDS -> null
        else -> copy(daysBefore = daysBefore + days)
    }

    /** Порог [days] убран; последний не убирается — без порогов напоминать не о чем. */
    fun withoutDay(days: Int): ExpiryReminderSettings = if (daysBefore.size <= 1) this else copy(daysBefore = daysBefore - days)

    companion object {
        const val MAX_DAYS: Int = 60
        const val MAX_THRESHOLDS: Int = 5
        const val DEFAULT_MINUTE: Int = 10 * 60
        val DEFAULT_DAYS: Set<Int> = setOf(5, 1, 0)
        val DEFAULT: ExpiryReminderSettings = ExpiryReminderSettings()

        /**
         * Значения из настроек телефона. Незнакомое или испорченное —
         * значение по умолчанию, как у [DEFAULT]: пользователь видит выбор
         * в «Настройках» и меняет его там.
         */
        fun of(enabled: Boolean, way: String?, days: String?, minuteOfDay: Int?): ExpiryReminderSettings = ExpiryReminderSettings(
            enabled = enabled,
            way = Way.entries.firstOrNull { it.wire == way } ?: DEFAULT.way,
            daysBefore = days?.let(::parseDays) ?: DEFAULT_DAYS,
            minuteOfDay = minuteOfDay?.takeIf { it in 0 until 24 * 60 } ?: DEFAULT_MINUTE,
        )

        /** Пороги для настроек: «5,1,0». */
        fun formatDays(days: Set<Int>): String = days.sortedDescending().joinToString(",")

        private fun parseDays(text: String): Set<Int>? {
            val days = text.split(',').map { it.trim().toIntOrNull() ?: return null }.toSet()
            return days.takeIf { it.isNotEmpty() && it.size <= MAX_THRESHOLDS && it.all { d -> d in 0..MAX_DAYS } }
        }
    }
}

/** Одно напоминание: подписка, её срок, порог и когда звучать. */
data class ExpiryReminder(
    val subscription: SubscriptionId,
    val name: String,
    val expireMillis: Long,
    val daysBefore: Int,
    val atMillis: Long,
) {
    /** Отметка «уже напомнили»: продление меняет срок, и у нового срока — свои напоминания. */
    val key: String get() = "${subscription.value}:$expireMillis:$daysBefore"
}

/**
 * Когда напоминать (D-76). Считает только телефон, по сроку из последнего
 * ответа поставщика — без сети и телеметрии (D-12); Android лишь будит в
 * назначенное время. Правило одно и проверяется на хосте.
 */
object ExpiryReminders {
    /** Опоздавшее больше чем на 15 минут — обычным уведомлением: будильник звонит только в выбранное время. */
    const val LATE_MILLIS: Long = 15 * 60_000L

    /** «Отложить» у будильника. */
    const val SNOOZE_MILLIS: Long = 10 * 60_000L

    /** Срок подписки в миллисекундах; null — поставщик его не сообщил (0 у поставщиков — «бессрочно»). */
    fun expireMillis(s: Subscription): Long? = s.metadata.traffic?.expireEpochSeconds?.takeIf { it > 0 }?.let { it * 1000 }

    /**
     * Все напоминания по сроку каждой подписки, по времени. Порог — день
     * за [ExpiryReminderSettings.daysBefore] дней до дня окончания, время
     * суток — выбранное, по часам телефона ([zone]). Напоминание в момент
     * окончания или позже пропускается: напоминать о продлении поздно,
     * а день до того — свой порог.
     */
    fun planned(subscriptions: List<Subscription>, settings: ExpiryReminderSettings, zone: ZoneId): List<ExpiryReminder> {
        if (!settings.enabled) return emptyList()
        val time = LocalTime.of(settings.minuteOfDay / 60, settings.minuteOfDay % 60)
        return subscriptions.flatMap { s ->
            val expire = expireMillis(s) ?: return@flatMap emptyList()
            val day = Instant.ofEpochMilli(expire).atZone(zone).toLocalDate()
            settings.daysBefore.mapNotNull { n ->
                val at = day.minusDays(n.toLong()).atTime(time).atZone(zone).toInstant().toEpochMilli()
                if (at >= expire) null else ExpiryReminder(s.id, s.displayName, expire, n, at)
            }
        }.sortedBy { it.atMillis }
    }

    /** Ближайшее напоминание впереди: на него ставится будильник Android. */
    fun next(planned: List<ExpiryReminder>, nowMillis: Long, done: Set<String>): ExpiryReminder? =
        planned.firstOrNull { it.atMillis > nowMillis && it.key !in done }

    /** Показать [reminder]; [late] — время прошло больше чем на [LATE_MILLIS]. */
    data class Shown(val reminder: ExpiryReminder, val late: Boolean)

    /** Что показать сейчас и отметки «уже напомнили» после показа. */
    data class Due(val show: List<Shown>, val done: Set<String>)

    /**
     * Что показать в [nowMillis]: по каждой подписке — последнее наступившее
     * напоминание, если о нём ещё не напоминали и срок не прошёл. Более
     * ранние пропущенные (телефон был выключен) уже не к месту — только
     * отмечаются: одно напоминание, а не залп.
     */
    fun due(planned: List<ExpiryReminder>, nowMillis: Long, done: Set<String>): Due {
        val passed = planned.filter { it.atMillis <= nowMillis && nowMillis < it.expireMillis }
        val show = passed.groupBy { it.subscription }.values
            .map { rs -> rs.maxBy { it.atMillis } }
            .filter { it.key !in done }
            .map { Shown(it, late = nowMillis - it.atMillis > LATE_MILLIS) }
        return Due(show, keep(planned, done + passed.map { it.key }))
    }

    /**
     * Настройку сменили: пороги, наступившие к [nowMillis], не звучат — они
     * уже позади на момент выбора, и сохранение настройки не будит
     * будильником. Новая подписка, срок которой уже близко, — напомнит.
     */
    fun afterChange(planned: List<ExpiryReminder>, nowMillis: Long, done: Set<String>): Set<String> =
        keep(planned, done + planned.filter { it.atMillis <= nowMillis }.map { it.key })

    /** Отметки — только о напоминаниях из плана: удалённые и продлённые подписки не копятся. */
    private fun keep(planned: List<ExpiryReminder>, done: Set<String>): Set<String> = done intersect planned.mapTo(HashSet()) { it.key }

    /** Сколько календарных дней до дня окончания (0 — сегодня) — для текста напоминания. */
    fun daysLeft(expireMillis: Long, nowMillis: Long, zone: ZoneId): Long =
        ChronoUnit.DAYS.between(Instant.ofEpochMilli(nowMillis).atZone(zone).toLocalDate(), Instant.ofEpochMilli(expireMillis).atZone(zone).toLocalDate())
}
