package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Состояние туннеля для интерфейса (D-34). */
class TunnelStatusTest {
    @Test
    fun busyMeansTunnelExistsOrIsComing() {
        assertTrue(TunnelStatus.Connecting(null).busy)
        assertTrue(TunnelStatus.Connected(ProfileId("a"), "A", 0).busy)
        assertFalse(TunnelStatus.Idle.busy)
        assertFalse(TunnelStatus.Stopping.busy)
        assertFalse(TunnelStatus.Failed(Diagnostic.error(DiagCode.ATTEMPTS_EXHAUSTED, "нет")).busy)
    }

    @Test
    fun rootCleanupFailureRequiresDisconnectWithoutClaimingTunBlock() {
        val reason = Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, "ROOT cleanup failed")
        val pending = TunnelStatus.Failed(reason, rootCleanupPending = true)
        assertTrue(pending.busy)
        assertFalse(pending.trafficBlocked)
        assertTrue(TunnelStatus.Failed(reason, trafficBlocked = true).busy)
        assertFalse(pending.copy(rootCleanupPending = false).busy)
    }

    @Test
    fun stateIsShared() {
        TunnelState.set(TunnelStatus.Connecting("A"))
        assertEquals(TunnelStatus.Connecting("A"), TunnelState.status.value)
        TunnelState.set(TunnelStatus.Idle)
        assertEquals(TunnelStatus.Idle, TunnelState.status.value)
    }
}

/** Скорость по счётчикам ядра (D-40). */
class TrafficMeterTest {
    @Test
    fun speedIsDeltaOverTimeAndNewSessionRestarts() {
        val m = TrafficMeter()
        assertEquals(Traffic(100, 1000, 0, 0), m.sample(com.dpsmpx.dppass.engine.TrafficStats(100, 1000), 0))
        assertEquals(Traffic(600, 3000, 250, 1000), m.sample(com.dpsmpx.dppass.engine.TrafficStats(600, 3000), 2000))
        // Счётчики уменьшились — новая сессия ядра: скорость с нуля, а не отрицательная.
        assertEquals(Traffic(10, 20, 0, 0), m.sample(com.dpsmpx.dppass.engine.TrafficStats(10, 20), 3000))
        // Время не прошло — без деления на ноль.
        assertEquals(Traffic(10, 20, 0, 0), m.sample(com.dpsmpx.dppass.engine.TrafficStats(10, 20), 3000))
    }

    @Test
    fun averagedTrafficUsesMeasuredBytesAndResets() {
        val m = TrafficMeter(5_000)
        fun sample(up: Long, down: Long, time: Long) =
            m.sample(com.dpsmpx.dppass.engine.TrafficStats(up, down), time)
        sample(0, 0, 0)
        sample(1000, 2000, 1000)
        assertEquals(Traffic(1000, 6000, 500, 3000), sample(1000, 6000, 2000))
        m.reset()
        assertEquals(Traffic(10, 20, 0, 0), sample(10, 20, 3000))
    }

    @Test
    fun notificationUpdatesEveryTwoSecondsOnlyWithScreenOn() {
        val pace = NotificationPace()
        // Десять секунд с включённым экраном — пять обновлений, через раз: раз в 2 с.
        val on = (0 until 10).map { pace.tick(interactive = true) }
        assertEquals(listOf(true, false, true, false, true, false, true, false, true, false), on)
        assertEquals(2_000L, NotificationPace.TICK_MILLIS * NotificationPace.NOTIFY_EVERY)
        // Экран выключен — ни одного обновления, счёт стоит.
        assertTrue((0 until 5).none { pace.tick(interactive = false) })
        // Снова включён — тот же шаг, без залпа.
        assertEquals(listOf(true, false, true), (0 until 3).map { pace.tick(interactive = true) })
    }

    @Test
    fun trafficResetsWhenTunnelGoesAway() {
        TunnelState.set(TunnelStatus.Connected(ProfileId("a"), "A", 0))
        TunnelState.traffic(Traffic(1, 2, 3, 4))
        TunnelState.set(TunnelStatus.Idle)
        assertEquals(Traffic.ZERO, TunnelState.traffic.value)
    }
}
