package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock

/**
 * Пауза между замерами по кнопке (D-61): сколько ещё ждать до следующего.
 * Замер — нагрузка на сервер, трафик тарифа и сигнал фильтру (L7), поэтому
 * подряд он не повторяется; пользователь видит, сколько осталось. Время —
 * монотонное и снаружи (D-21). Доступ под замком: пишет замер, читает экран.
 */
class Cooldown(private val clock: Clock) {
    private var until: Long? = null

    /** 0 — можно сейчас. */
    @Synchronized
    fun remainingMillis(): Long = until?.let { (it - clock.nowMillis()).coerceAtLeast(0) } ?: 0

    /** Замер закончился: следующий — не раньше чем через [periodMillis]. */
    @Synchronized
    fun restart(periodMillis: Long) {
        require(periodMillis >= 0)
        until = clock.nowMillis() + periodMillis
    }
}
