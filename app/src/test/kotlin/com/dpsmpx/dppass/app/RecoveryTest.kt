package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** Расписание восстановления (D-113): пауза растёт и упирается в предел, уведомление — не с первой попытки. */
class RecoveryTest {
    @Test
    fun delayGrowsAndIsCapped() {
        assertEquals(listOf(5_000L, 10_000L, 20_000L, 40_000L, 60_000L, 60_000L), (0..5).map(Recovery::delayMillis))
        assertEquals(60_000L, Recovery.delayMillis(1_000), "огромное число попыток не переполняет сдвиг")
        assertEquals(5_000L, Recovery.delayMillis(-3))
    }

    @Test
    fun successfulRestartWithoutNetworkMustKeepWaiting() {
        assertEquals(
            Recovery.AttemptResult.WAIT_FOR_NETWORK,
            Recovery.afterAttempt(connected = true, blockedFailure = false, networkUp = false),
            "ядро сообщило Connected, но сеть уже пропала",
        )
        assertEquals(
            Recovery.AttemptResult.RESTORED,
            Recovery.afterAttempt(connected = true, blockedFailure = false, networkUp = true),
        )
        assertEquals(
            Recovery.AttemptResult.WAIT_FOR_NETWORK,
            Recovery.afterAttempt(connected = false, blockedFailure = true, networkUp = false),
            "сбой из-за отсутствия сети не засчитывается серверу",
        )
        assertEquals(
            Recovery.AttemptResult.RETRY,
            Recovery.afterAttempt(connected = false, blockedFailure = true, networkUp = true),
        )
        assertEquals(
            Recovery.AttemptResult.STOP,
            Recovery.afterAttempt(connected = false, blockedFailure = false, networkUp = false),
            "если туннеля больше нет, восстановление заканчивается",
        )
    }

    @Test
    fun userIsToldOnlyAfterSeveralFailures() {
        assertTrue(Recovery.NOTIFY_AFTER >= 2, "одна неудача при вернувшейся сети — ещё не повод беспокоить")
        assertTrue(Recovery.SETTLE_MILLIS > 0)
    }
}
