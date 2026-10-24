package com.dpsmpx.dppass.subscriptions

import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.Secret
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Напоминание о конце подписки (D-76): когда звучать, что показать, что отметить. */
class ExpiryRemindersTest {
    private val zone = ZoneId.of("Europe/Moscow")
    private val on = ExpiryReminderSettings(enabled = true)

    private fun at(day: Int, hour: Int, minute: Int = 0): Long = ZonedDateTime.of(2026, 10, day, hour, minute, 0, 0, zone).toInstant().toEpochMilli()

    private fun sub(id: String, expireMillis: Long?): Subscription = Subscription(
        SubscriptionId(id),
        "Подписка $id",
        SubscriptionSource.Url(Secret("https://sub.example.com/$id")),
        metadata = SubscriptionMetadata(traffic = TrafficInfo(null, null, null, expireMillis?.let { it / 1000 })),
    )

    @Test
    fun thresholdsAreDaysBeforeTheEndDayAtTheChosenTime() {
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on, zone)
        assertEquals(listOf(at(25, 10), at(29, 10), at(30, 10)), plan.map { it.atMillis })
        assertEquals(listOf(5, 1, 0), plan.map { it.daysBefore })
        // Своё время суток.
        val evening = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on.copy(minuteOfDay = 20 * 60 + 30), zone)
        assertEquals(at(25, 20, 30), evening.first().atMillis)
    }

    @Test
    fun reminderAtOrAfterTheEndIsSkipped() {
        // Конец в 03:00: «в день окончания» в 10:00 — уже поздно; «за день» остаётся.
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 3))), on, zone)
        assertEquals(listOf(5, 1), plan.map { it.daysBefore })
    }

    @Test
    fun nothingWithoutConsentOrDate() {
        assertTrue(ExpiryReminders.planned(listOf(sub("a", at(30, 15))), ExpiryReminderSettings.DEFAULT, zone).isEmpty(), "выключено по умолчанию")
        assertTrue(ExpiryReminders.planned(listOf(sub("a", null)), on, zone).isEmpty(), "срока нет — напоминать не о чем")
        assertTrue(ExpiryReminders.planned(listOf(sub("a", 0)), on, zone).isEmpty(), "0 у поставщиков — бессрочно")
    }

    @Test
    fun onTimeIsAlarmLateIsOneNotificationNotABurst() {
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on, zone)
        val onTime = ExpiryReminders.due(plan, at(25, 10) + 30_000, emptySet())
        assertEquals(listOf(5), onTime.show.map { it.reminder.daysBefore })
        assertEquals(false, onTime.show.single().late)
        // Повторно — не показывается; следующее — за день.
        assertTrue(ExpiryReminders.due(plan, at(25, 11), onTime.done).show.isEmpty())
        assertEquals(1, ExpiryReminders.next(plan, at(25, 11), onTime.done)?.daysBefore)

        // Телефон был выключен с 24-го: в 12:00 29-го — только последнее наступившее, и не будильником.
        val late = ExpiryReminders.due(plan, at(29, 12), emptySet())
        assertEquals(listOf(1), late.show.map { it.reminder.daysBefore })
        assertTrue(late.show.single().late)
        assertTrue(plan.filter { it.daysBefore >= 1 }.all { it.key in late.done }, "пропущенное раньше — отмечено")
        assertEquals(0, ExpiryReminders.next(plan, at(29, 12), late.done)?.daysBefore)
    }

    @Test
    fun afterTheEndNothingIsShown() {
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on, zone)
        assertTrue(ExpiryReminders.due(plan, at(30, 16), emptySet()).show.isEmpty())
        assertNull(ExpiryReminders.next(plan, at(30, 16), emptySet()))
    }

    @Test
    fun changingSettingsDoesNotRingForThresholdsAlreadyPassed() {
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on, zone)
        val done = ExpiryReminders.afterChange(plan, at(27, 9), emptySet())
        assertTrue(ExpiryReminders.due(plan, at(27, 9), done).show.isEmpty(), "за 5 дней — уже позади на момент выбора")
        assertEquals(1, ExpiryReminders.next(plan, at(27, 9), done)?.daysBefore)
    }

    @Test
    fun renewalStartsNewRemindersAndOldMarksAreDropped() {
        val old = ExpiryReminders.planned(listOf(sub("a", at(30, 15))), on, zone)
        val done = ExpiryReminders.due(old, at(29, 10), emptySet()).done
        // Продлили: срок — через месяц; у нового срока свои напоминания, отметки старого не держатся.
        val renewed = ExpiryReminders.planned(listOf(sub("a", at(30, 15) + 31L * 24 * 3_600_000)), on, zone)
        val after = ExpiryReminders.due(renewed, at(29, 11), done)
        assertTrue(after.show.isEmpty())
        assertTrue(after.done.isEmpty())
        assertEquals(5, ExpiryReminders.next(renewed, at(29, 11), after.done)?.daysBefore)
    }

    @Test
    fun eachSubscriptionGetsItsOwnReminder() {
        val plan = ExpiryReminders.planned(listOf(sub("a", at(30, 15)), sub("b", at(30, 18))), on, zone)
        val due = ExpiryReminders.due(plan, at(29, 10, 1), emptySet())
        assertEquals(setOf("a", "b"), due.show.map { it.reminder.subscription.value }.toSet())
    }

    @Test
    fun settingsFromPhoneStorage() {
        assertEquals(on.copy(way = ExpiryReminderSettings.Way.ALARM), ExpiryReminderSettings.of(true, "alarm", "0,1,5", 600))
        assertEquals("5,1,0", ExpiryReminderSettings.formatDays(setOf(0, 5, 1)))
        // Порча и настройки будущих выпусков — значения по умолчанию.
        val broken = ExpiryReminderSettings.of(true, "siren", "5,x", 24 * 60)
        assertEquals(on, broken)
        assertEquals(ExpiryReminderSettings.DEFAULT_DAYS, ExpiryReminderSettings.of(true, null, "61", null).daysBefore)
        assertEquals(ExpiryReminderSettings.DEFAULT_DAYS, ExpiryReminderSettings.of(true, null, "1,2,3,4,5,6", null).daysBefore)
    }

    @Test
    fun thresholdsAreBounded() {
        assertNull(on.withDay(-1))
        assertNull(on.withDay(ExpiryReminderSettings.MAX_DAYS + 1))
        assertEquals(setOf(5, 1, 0, 3), on.withDay(3)?.daysBefore)
        assertNull(on.withDay(3)?.withDay(7)?.withDay(10), "не больше пяти порогов")
        assertEquals(on, on.withDay(5), "уже есть")
        val one = on.withoutDay(5).withoutDay(1)
        assertEquals(setOf(0), one.daysBefore)
        assertEquals(one, one.withoutDay(0), "последний порог не убирается")
    }

    @Test
    fun daysLeftCountsCalendarDays() {
        assertEquals(0, ExpiryReminders.daysLeft(at(30, 23), at(30, 1), zone))
        assertEquals(1, ExpiryReminders.daysLeft(at(30, 1), at(29, 23), zone))
        assertEquals(5, ExpiryReminders.daysLeft(at(30, 15), at(25, 10), zone))
    }
}
