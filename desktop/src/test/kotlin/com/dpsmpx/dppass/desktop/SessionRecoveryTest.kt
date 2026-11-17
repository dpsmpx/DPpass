package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Восстановление сеанса на ПК (D-115): без сети — ни попыток, ни отказов;
 * сеть вернулась — проба, затем ядро заново тем же сервером; не вышло три
 * раза — сообщение, а не другой сервер.
 */
class SessionRecoveryTest {
    private val sink = MemoryLogSink()
    private val log = Logger("test", sink, { 0L })

    /** Мир восстановления: время, сеть, проба и перезапуск — подделки с журналом вызовов. */
    private inner class World(
        /** Есть ли сеть в момент [now]. */
        val network: (Long) -> Boolean = { true },
        /** Исход пробы через работающее ядро; null — ядро стоит. */
        val probe: (Long) -> Outcome<Unit>? = { fail("ни байта") },
        /** Исход перезапуска; null — платформа не перезапускает ядро (Windows). */
        val restart: ((Long) -> Outcome<Unit>)? = { fail("сервер не отвечает") },
        /** Сколько идёт перезапуск: подключение с пробой — не мгновенно. */
        val restartMillis: Long = 0,
    ) {
        var now = 0L
        val calls = mutableListOf<String>()
        var waiting = 0
        val failures = mutableListOf<Int>()
        val notified = mutableListOf<Int>()

        private val events = object : SessionRecovery.Events {
            override fun waitingNetwork() {
                waiting++
                calls += "waiting@$now"
            }

            override fun attempting(attempt: Int) {
                calls += "attempt$attempt@$now"
            }

            override fun failed(reason: Diagnostic, attempts: Int) {
                failures += attempts
            }

            override fun unreachable(reason: Diagnostic, attempts: Int) {
                notified += attempts
                calls += "unreachable@$now"
            }
        }

        val recovery = SessionRecovery(
            log,
            { network(now) },
            {
                calls += "probe@$now"
                probe(now)
            },
            restart?.let { r ->
                {
                    calls += "restart@$now"
                    r(now).also { now += restartMillis }
                }
            },
            events,
        )

        /** До восстановления или до [limit] мс. true — восстановлено. */
        fun run(degraded: Diagnostic? = null, failedBefore: Int = 0, limit: Long = 600_000): Boolean = runBlocking {
            try {
                recovery.run({ ms ->
                    now += ms
                    if (now > limit) throw Stop()
                }, degraded, failedBefore)
                true
            } catch (_: Stop) {
                false
            }
        }
    }

    /** Время теста вышло — восстановление не закончилось. */
    private class Stop : RuntimeException("предел теста")

    private fun fail(why: String): Outcome<Unit> = Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, why)

    @Test
    fun noNetworkMeansNoAttemptsAndNoFailures() {
        val w = World(network = { false })
        assertTrue(!w.run(limit = 300_000), "сети нет пять минут — восстановления нет, но и отказа нет")
        assertEquals(1, w.waiting, "о пропаже сети — один раз, а не на каждом опросе")
        assertTrue(w.calls.none { it.startsWith("probe") || it.startsWith("restart") }, "без сети ничего не пробуется: ${w.calls}")
        assertTrue(w.failures.isEmpty(), "пропажа сети — не отказ сервера")
        assertTrue(sink.snapshot().none { it.event == "recovery_failed" })
    }

    @Test
    fun networkBackThenProbeThroughTheRunningCoreRecovers() {
        // Сеть пропала на минуту и вернулась; ядро не останавливалось — проба проходит.
        val w = World(network = { it >= 60_000 }, probe = { Outcome.Success(Unit) })
        assertTrue(w.run())
        val probe = w.calls.first { it.startsWith("probe") }
        assertTrue(probe.substringAfter('@').toLong() >= 60_000 + SessionRecovery.SETTLE_MILLIS, "после возвращения — пауза, сеть устояться: ${w.calls}")
        assertTrue(w.calls.none { it.startsWith("restart") }, "ядро работало — перезапуск не нужен")
        assertTrue(sink.snapshot().any { it.event == "network_restored" })
        assertTrue(sink.snapshot().any { it.event == "recovery_done" && it.fields["by"] == "probe" })
    }

    @Test
    fun failedProbeRestartsTheCoreWithTheSameServer() {
        val w = World(restart = { Outcome.Success(Unit) })
        assertTrue(w.run())
        assertEquals(listOf("attempt1", "probe", "restart"), w.calls.map { it.substringBefore('@') })
    }

    @Test
    fun confirmedDegradationRestartsAtOnceWithoutProbe() {
        // Наблюдатель уже подтвердил сбой при живой сети (D-58): сразу перезапуск, без паузы и пробы.
        val w = World(restart = { Outcome.Success(Unit) })
        assertTrue(w.run(degraded = Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "череда сбоев")))
        assertEquals(listOf("attempt1@0", "restart@0"), w.calls)
    }

    @Test
    fun unreachableServerIsReportedAfterThreeAttemptsAndAttemptsGoOn() {
        val w = World()
        assertTrue(!w.run(limit = 400_000))
        assertEquals(listOf(SessionRecovery.NOTIFY_AFTER), w.notified, "сообщение — один раз, после трёх неудач")
        val attempts = w.calls.filter { it.startsWith("restart") }.map { it.substringAfter('@').toLong() }
        assertTrue(attempts.size > SessionRecovery.NOTIFY_AFTER + 2, "после сообщения попытки идут дальше: $attempts")
        // Паузы между попытками растут: 5, 10, 20, 40 с, дальше — раз в минуту.
        val gaps = attempts.zipWithNext { a, b -> b - a }
        assertEquals(listOf(5_000L, 10_000L, 20_000L, 40_000L, 60_000L), gaps.take(5))
        assertTrue(gaps.drop(4).all { it == 60_000L })
    }

    @Test
    fun networkLostMidAttemptIsNotCountedAgainstTheServer() {
        // Перезапуск идёт 2 с, и на первый пришлась пропажа сети (4–30 с): он не засчитан серверу.
        val w = World(network = { it !in 4_000 until 30_000 }, probe = { null }, restartMillis = 2_000)
        assertTrue(!w.run(limit = 40_000))
        assertEquals(2, w.calls.count { it.startsWith("restart") })
        assertEquals(listOf(1), w.failures, "засчитана только попытка при живой сети")
        assertEquals(1, w.waiting)
        assertEquals(1, sink.snapshot().count { it.event == "recovery_failed" })
    }

    @Test
    fun windowsDoesNotRestartTheCoreOnlyProbes() {
        // Windows (D-97): адаптер живёт с ядром — ради восстановления ядро не останавливается.
        val w = World(restart = null)
        assertTrue(!w.run(limit = 120_000))
        assertTrue(w.calls.none { it.startsWith("restart") })
        assertTrue(w.calls.count { it.startsWith("probe") } >= SessionRecovery.NOTIFY_AFTER)
        assertEquals(listOf(SessionRecovery.NOTIFY_AFTER), w.notified)
    }

    @Test
    fun restartByButtonThatJustFailedWaitsForTheSchedule() {
        val w = World(restart = { Outcome.Success(Unit) })
        assertTrue(w.run(degraded = Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "не вышло по кнопке"), failedBefore = 1))
        assertEquals(listOf("attempt2@5000", "restart@5000"), w.calls, "после неудачи по кнопке — пауза расписания, а не вторая попытка сразу")
    }

    @Test
    fun pinHoldsTheServerWhileAutoSwitchIsOff() {
        val a = ProfileId("server-a")
        val b = ProfileId("server-b")
        val present = listOf(a, b)
        assertEquals(a, ServerPin.target(autoSwitch = false, selected = a, pin = null, present = present), "выбранный пользователем")
        assertNull(ServerPin.target(autoSwitch = true, selected = a, pin = null, present = present), "автопереключение включено — согласие на замену")
        // «Автоматически»: держится тот, к которому подключились.
        val auto = ServerPin.Pin(b, selectedAt = null)
        assertEquals(b, ServerPin.target(autoSwitch = false, selected = null, pin = auto, present = present))
        // Пользователь выбрал сервер — закрепление «Автоматически» уступает выбору.
        assertEquals(a, ServerPin.target(autoSwitch = false, selected = a, pin = auto, present = present))
        // Выбор сменился с сервера на «Автоматически» — прежнее закрепление не действует.
        assertNull(ServerPin.target(autoSwitch = false, selected = null, pin = ServerPin.Pin(a, selectedAt = a), present = present))
        // Сервера больше нет в подписке — держать нечего, а не чужой.
        assertNull(ServerPin.target(autoSwitch = false, selected = null, pin = auto, present = listOf(a)))
    }
}
