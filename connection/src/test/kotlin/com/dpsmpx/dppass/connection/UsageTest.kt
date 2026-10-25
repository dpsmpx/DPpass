package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import java.time.LocalDate
import java.time.ZoneId
import java.time.ZonedDateTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Учёт трафика через сервер (D-92): сутки, период, сети, порог, сброс, хранение. */
class UsageTest {
    private val zone = ZoneId.of("Europe/Moscow")
    private val clock = ManualClock(at(2026, 8, 1))
    private val blobs = InMemoryBlobStore()

    private fun at(y: Int, m: Int, d: Int, h: Int = 0): Long = ZonedDateTime.of(y, m, d, h, 0, 0, 0, zone).toInstant().toEpochMilli()

    /** Часы теста — только вперёд. */
    private fun moveTo(y: Int, m: Int, d: Int, h: Int = 12) = clock.advance(at(y, m, d, h) - clock.nowMillis())

    private fun service() = UsageService(UsageStore(blobs, Quarantine(blobs, clock)), clock) { zone }

    private fun day(y: Int, m: Int, d: Int) = LocalDate.of(y, m, d)

    @Test
    fun periodStartsOnTheChosenDayAndOnTheLastDayOfShortMonths() {
        assertEquals(day(2026, 10, 1) to day(2026, 11, 1), UsagePeriod.of(day(2026, 10, 25), 1))
        assertEquals(day(2026, 10, 5) to day(2026, 11, 5), UsagePeriod.of(day(2026, 10, 25), 5))
        assertEquals(day(2026, 9, 26) to day(2026, 10, 26), UsagePeriod.of(day(2026, 10, 25), 26), "до дня начала — прошлый период")
        assertEquals(day(2026, 10, 25) to day(2026, 11, 25), UsagePeriod.of(day(2026, 10, 25), 25), "в день начала — новый период")
        // 31-е: в феврале периода начинается 28-го, в апреле — 30-го; дни не выпадают и не повторяются.
        assertEquals(day(2027, 1, 31) to day(2027, 2, 28), UsagePeriod.of(day(2027, 2, 10), 31))
        assertEquals(day(2027, 2, 28) to day(2027, 3, 31), UsagePeriod.of(day(2027, 3, 1), 31))
        assertEquals(day(2027, 3, 31) to day(2027, 4, 30), UsagePeriod.of(day(2027, 4, 29), 31))
        assertEquals(day(2028, 2, 29) to day(2028, 3, 30), UsagePeriod.of(day(2028, 3, 1), 30), "високосный февраль — 29-е")
    }

    @Test
    fun todayAndPeriodAreCountedPerNetwork() {
        moveTo(2026, 10, 25)
        val u = service()
        u.record(UsageBytes(100, 1_000), NetworkType.MOBILE)
        u.record(UsageBytes(10, 200), NetworkType.WIFI)
        u.record(UsageBytes(1, 2), NetworkType.NONE)
        clock.advance(24 * 3600_000L)
        u.record(UsageBytes(5, 50), NetworkType.MOBILE)
        val s = u.summary()
        assertEquals(mapOf(NetworkType.MOBILE to UsageBytes(5, 50)), s.today, "сегодня — только новые сутки")
        assertEquals(UsageBytes(105, 1_050), s.period[NetworkType.MOBILE])
        assertEquals(UsageBytes(10, 200), s.period[NetworkType.WIFI])
        assertEquals(UsageBytes(1, 2), s.period[NetworkType.OTHER], "без известной сети — «другие», не теряется")
        assertEquals(UsageBytes(116, 1_252), s.periodTotal)
        assertEquals(day(2026, 10, 1), s.periodStart)
        assertEquals(1_155, s.mobilePeriodBytes)
    }

    @Test
    fun daysAreLocalNotUtc() {
        moveTo(2026, 10, 26, 1)
        // 01:00 по Москве — ещё 25-е по UTC: сутки — по часам пользователя.
        val u = service()
        u.record(UsageBytes(1, 1), NetworkType.WIFI)
        assertEquals(UsageBytes(1, 1), u.summary().today[NetworkType.WIFI])
        u.flush()
        val stored = UsageCodec.read(String(blobs.read(UsageStore.KEY).valueOrNull()!!)).valueOrNull()!!
        assertEquals(setOf(day(2026, 10, 26)), stored.days.keys)
    }

    @Test
    fun mobileLimitAlertsOncePerPeriodAndSurvivesRestart() {
        moveTo(2026, 10, 25)
        val u = service()
        assertTrue(u.setSettings(UsageSettings(periodStartDay = 1, mobileLimitBytes = 1_000)) is Outcome.Success)
        assertNull(u.record(UsageBytes(0, 600), NetworkType.MOBILE))
        assertNull(u.record(UsageBytes(0, 900), NetworkType.WIFI), "Wi-Fi порог мобильной сети не трогает")
        val alert = assertNotNull(u.record(UsageBytes(0, 400), NetworkType.MOBILE), "порог пройден — сказать")
        assertEquals(1_000, alert.usedBytes)
        assertEquals(1_000, alert.limitBytes)
        assertEquals(day(2026, 10, 1), alert.periodStart)
        assertNull(u.record(UsageBytes(0, 400), NetworkType.MOBILE), "второй раз в периоде — молчать")
        assertNull(service().record(UsageBytes(0, 1), NetworkType.MOBILE), "и после перезапуска процесса")
        // Новый период — новый счёт и новое предупреждение.
        moveTo(2026, 11, 1, 9)
        val u2 = service()
        assertNull(u2.record(UsageBytes(0, 999), NetworkType.MOBILE))
        assertNotNull(u2.record(UsageBytes(0, 1), NetworkType.MOBILE))
    }

    @Test
    fun newLimitRearmsTheAlert() {
        moveTo(2026, 10, 25)
        val u = service()
        u.setSettings(UsageSettings(mobileLimitBytes = 100))
        assertNotNull(u.record(UsageBytes(0, 150), NetworkType.MOBILE))
        u.setSettings(UsageSettings(mobileLimitBytes = 200))
        assertNull(u.record(UsageBytes(0, 10), NetworkType.MOBILE))
        assertNotNull(u.record(UsageBytes(0, 50), NetworkType.MOBILE), "новый порог пройден — сказать снова")
    }

    @Test
    fun resetStartsTheCountNowAndKeepsEarlierPeriods() {
        moveTo(2026, 10, 3, 12)
        val u = service()
        u.setSettings(UsageSettings(periodStartDay = 5, mobileLimitBytes = 100))
        u.record(UsageBytes(0, 70), NetworkType.MOBILE) // период 5 сентября — 5 октября
        moveTo(2026, 10, 10, 12)
        assertNotNull(u.record(UsageBytes(0, 150), NetworkType.MOBILE))
        assertTrue(u.reset() is Outcome.Success)
        val s = u.summary()
        assertEquals(0, s.periodTotal.total)
        assertEquals(0, s.todayTotal.total)
        assertEquals(clock.nowMillis(), s.resetAtMillis)
        assertNotNull(u.record(UsageBytes(0, 100), NetworkType.MOBILE), "после сброса порог считается заново")
        val st = UsageStore(blobs, Quarantine(blobs, clock)).load().valueOrNull()!!
        assertEquals(UsageBytes(0, 70), st.days[day(2026, 10, 3)]?.get(NetworkType.MOBILE), "прошлый период сброс не трогает")
        // Следующий период — отметки сброса в сводке нет.
        moveTo(2026, 11, 6, 12)
        assertNull(service().summary().resetAtMillis)
    }

    @Test
    fun savesAtMostOnceAMinuteAndOnFlush() {
        moveTo(2026, 10, 25)
        val u = service()
        u.record(UsageBytes(1, 1), NetworkType.WIFI)
        val first = blobs.read(UsageStore.KEY).valueOrNull()
        assertNotNull(first, "первая запись — сразу")
        clock.advance(10_000)
        u.record(UsageBytes(1, 1), NetworkType.WIFI)
        assertEquals(String(first), String(blobs.read(UsageStore.KEY).valueOrNull()!!), "через 10 с диск не трогается")
        assertTrue(u.flush() is Outcome.Success)
        assertEquals(UsageBytes(2, 2), service().summary().today[NetworkType.WIFI], "после остановки — всё на диске")
        clock.advance(UsageService.SAVE_EVERY_MILLIS)
        u.record(UsageBytes(1, 1), NetworkType.WIFI)
        assertEquals(UsageBytes(3, 3), service().summary().today[NetworkType.WIFI], "через минуту — сам")
    }

    @Test
    fun oldDaysArePrunedButPreviousPeriodStays() {
        moveTo(2026, 8, 20, 12)
        val u = service()
        u.record(UsageBytes(0, 1), NetworkType.WIFI)
        moveTo(2026, 9, 20, 12)
        u.record(UsageBytes(0, 2), NetworkType.WIFI)
        moveTo(2026, 10, 20, 12)
        u.record(UsageBytes(0, 3), NetworkType.WIFI)
        val st = UsageStore(blobs, Quarantine(blobs, clock)).load().valueOrNull()!!
        assertEquals(setOf(day(2026, 9, 20), day(2026, 10, 20)), st.days.keys, "август — позапрошлый период, не хранится")
    }

    @Test
    fun badSettingsAreRefusedWithReason() {
        moveTo(2026, 10, 25)
        val u = service()
        val bad = listOf(
            UsageSettings(periodStartDay = 0),
            UsageSettings(periodStartDay = 32),
            UsageSettings(mobileLimitBytes = 0),
            UsageSettings(mobileLimitBytes = UsageSettings.MAX_LIMIT_BYTES + 1),
        )
        for (b in bad) {
            val r = u.setSettings(b)
            assertTrue(r is Outcome.Failure && r.errors.first().code == DiagCode.USAGE_SETTING_INVALID, "$b")
        }
        assertEquals(UsageSettings(), u.settings(), "отказ ничего не меняет")
    }

    @Test
    fun codecRoundTripAndCorruptedRecordGoesToQuarantine() {
        moveTo(2026, 10, 25)
        val st = UsageState(
            UsageSettings(15, 15L shl 30),
            mapOf(day(2026, 10, 24) to mapOf(NetworkType.MOBILE to UsageBytes(1, 2), NetworkType.ETHERNET to UsageBytes(3, 4))),
            resetAtMillis = 123,
            alertedPeriod = day(2026, 10, 15),
        )
        assertEquals(st, UsageCodec.read(UsageCodec.write(st)).valueOrNull())
        blobs.write(UsageStore.KEY, """{"format":"dppass.usage","format_version":1,"period_start_day":40,"days":[]}""".toByteArray())
        val r = UsageStore(blobs, Quarantine(blobs, clock)).load()
        assertEquals(UsageState(), r.valueOrNull(), "не прочитать — счёт с нуля")
        assertEquals(DiagCode.STORAGE_CORRUPTED, r.diagnostics.single().code)
        assertTrue(blobs.keys("quarantine/").valueOrNull().orEmpty().isNotEmpty(), "исходник — в карантине")
        val future = UsageCodec.read("""{"format":"dppass.usage","format_version":2}""")
        assertTrue(future is Outcome.Failure && future.errors.first().code == DiagCode.FORMAT_VERSION_UNSUPPORTED)
    }

    @Test
    fun thresholdIsTypedInGigabytes() {
        assertEquals(15L shl 30, UsageSettings.parseGigabytes("15"))
        assertEquals(3L shl 29, UsageSettings.parseGigabytes(" 1,5 "), "запятая — как в русской раскладке")
        assertEquals(3L shl 29, UsageSettings.parseGigabytes("1.5"))
        for (bad in listOf("", "0", "-1", "abc", "NaN", "Infinity", "2000000")) assertNull(UsageSettings.parseGigabytes(bad), bad)
        assertEquals("15", UsageSettings.gigabytes(15L shl 30))
        assertEquals("1.5", UsageSettings.gigabytes(3L shl 29))
        assertEquals(3L shl 29, UsageSettings.parseGigabytes(UsageSettings.gigabytes(3L shl 29)), "поле с прежним порогом — тот же порог")
    }

    @Test
    fun meterTurnsSessionCountersIntoIncrements() {
        val m = UsageMeter()
        assertEquals(UsageBytes(10, 100), m.delta(TrafficStats(10, 100)), "первое чтение — всё с начала сеанса")
        assertEquals(UsageBytes(5, 50), m.delta(TrafficStats(15, 150)))
        assertEquals(UsageBytes(0, 0), m.delta(TrafficStats(15, 150)))
        assertEquals(UsageBytes(3, 30), m.delta(TrafficStats(3, 30)), "убыль — новый сеанс ядра: его счётчики и есть приращение")
    }
}
