package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock

/**
 * Проверка сети при её смене (D-67): что считать сменой и когда после неё
 * проверять. Один экземпляр на сессию туннеля.
 *
 * - Первая сеть сессии — не смена: её режим взят при подключении (D-64).
 *   Та же сеть снова (система повторяет уведомление) — тоже не смена.
 * - Проверка — через [settleMillis] после последней смены: сеть ещё
 *   устанавливается (страница входа, регистрация в сети оператора). Новая
 *   смена за это время — отсчёт заново, для новой сети.
 * - Не больше [maxPerHour] проверок за час: телефон на границе Wi-Fi
 *   переходит то туда, то сюда, и проверка на каждую смену была бы залпом
 *   к ориентирам — сама сигнал фильтру (L7, D-14).
 *
 * Сеть — непрозрачный ключ (на Android — `Network.getNetworkHandle()`),
 * время — монотонное и снаружи (D-21). Доступ под замком: о сети сообщает
 * система из своего потока, проверку ведёт сервис.
 */
class NetworkChangeChecks(
    private val clock: Clock,
    private val settleMillis: Long = SETTLE_MILLIS,
    private val maxPerHour: Int = MAX_PER_HOUR,
) {
    private var network: Long? = null
    private var changedAt: Long? = null
    private val started = ArrayDeque<Long>()

    init {
        require(settleMillis >= 0 && maxPerHour > 0)
    }

    /** Сеть по умолчанию теперь [network]. true — это смена. */
    @Synchronized
    fun onNetwork(network: Long): Boolean {
        val previous = this.network
        this.network = network
        if (previous == null || previous == network) return false
        changedAt = clock.nowMillis()
        return true
    }

    /**
     * Сколько ждать до проверки сети [network] (0 — пора); null — проверять
     * её не нужно: сеть уже другая или смены не было.
     */
    @Synchronized
    fun waitMillis(network: Long): Long? {
        val at = changedAt ?: return null
        if (this.network != network) return null
        return (at + settleMillis - clock.nowMillis()).coerceAtLeast(0)
    }

    /**
     * Начать проверку сети [network]: она всё ещё текущая, пауза прошла и
     * предел за час не исчерпан. true — проверка засчитана в предел, и
     * следующая без новой смены не начнётся.
     */
    @Synchronized
    fun tryStart(network: Long): Boolean {
        if (waitMillis(network) != 0L) return false
        val now = clock.nowMillis()
        while (started.isNotEmpty() && now - started.first() >= HOUR_MILLIS) started.removeFirst()
        if (started.size >= maxPerHour) return false
        started.addLast(now)
        changedAt = null
        return true
    }

    companion object {
        /** Пауза после смены — ориентир, не замер: сверка — на телефоне (`TODO.md`). */
        const val SETTLE_MILLIS: Long = 20_000
        const val MAX_PER_HOUR: Int = 4
        private const val HOUR_MILLIS: Long = 60L * 60 * 1000
    }
}
