package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.RestrictionClass
import kotlinx.coroutines.Job
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch

/**
 * Смена сети ПК под туннелем (D-80, к D-67) — как у сервиса туннеля Android.
 * Пока сеанс идёт, раз в [POLL_MILLIS] — сеть ПК ([DesktopHost.network]:
 * маршрут по умолчанию таблицы `main` на Linux, мимо адаптера DPpass на
 * Windows). Сменилась — режим сессии заново (у новой сети
 * он неизвестен); через паузу [NetworkChangeChecks] — проверка новой сети
 * (D-79), если она не выключена, и режим ещё раз. Что считать сменой, пауза
 * и предел за час — [NetworkChangeChecks], одни на время работы туннеля.
 *
 * Маршрутов и правил смена сети не трогает: сокеты ядра с меткой идут по
 * таблице `main`, и она уже ведёт в новую сеть (D-74); на Windows ядро само
 * привязывает сокеты к новому интерфейсу (`autoOutboundsInterface`, D-97).
 * Зависший после смены сеанс ловит наблюдатель (D-78).
 */
class NetworkWatch(
    private val log: Logger,
    private val check: DesktopNetworkCheck,
    private val changes: NetworkChangeChecks,
    /** «Проверять сеть при её смене»: выключено — только по кнопке (D-79). */
    private val enabled: () -> Boolean,
    /** Режим сессии взят заново: наблюдателю — новый контекст опыта (D-64). */
    private val retaken: (NetworkAssessment?) -> Unit,
    private val current: () -> DesktopNetwork? = LinuxNetwork::current,
) {
    private var registered = false
    private var known: Long? = null
    private var type: NetworkType = NetworkType.NONE

    /** Взглянуть на сеть: ключ новой сети, если это смена; иначе null. */
    fun observe(): Long? {
        val n = current()
        val key = n?.key
        if (registered && key == known) return null
        registered = true
        val from = type
        known = key
        type = n?.type ?: NetworkType.NONE
        log.info("underlying_network", "state" to Safe(if (key == null) "lost" else "available"), "type" to type)
        if (key == null || !changes.onNetwork(key)) return null
        log.info("network_changed", "from" to from, "to" to type)
        retake("network_changed")
        return key
    }

    /**
     * После смены на [network]: пауза, затем проверка новой сети. Пропуск —
     * с причиной в журнале: выключено, сеть уже другая, предел за час.
     */
    suspend fun afterChange(network: Long, sleep: suspend (Long) -> Unit) {
        while (true) {
            // null — сеть уже другая: её проверит своя смена.
            val wait = changes.waitMillis(network) ?: return
            if (wait == 0L) break
            sleep(wait)
        }
        if (!enabled()) {
            log.info("network_check_skipped", "reason" to Safe("disabled"))
            return
        }
        // Проверка по кнопке только что потратила бюджет (D-14): подождать, а не идти с пропусками.
        sleep(check.readyInMillis())
        val skipped = when {
            changes.waitMillis(network) == null -> "network_gone"
            !changes.tryStart(network) -> "limit"
            else -> null
        }
        if (skipped != null) {
            log.info("network_check_skipped", "reason" to Safe(skipped))
            return
        }
        if (check.run(DesktopNetworkCheck.Trigger.NETWORK_CHANGE) == null) {
            // Идёт проверка по кнопке — её итог и будет итогом новой сети.
            while (check.busy()) sleep(BUSY_POLL_MILLIS)
        }
        retake("network_checked")
    }

    /** До отмены (остановка сеанса): опрос сети и проверка после каждой смены; новая смена отменяет прежнюю проверку. */
    suspend fun run(sleep: suspend (Long) -> Unit): Unit = coroutineScope {
        var pending: Job? = null
        while (true) {
            observe()?.let { network ->
                pending?.cancel()
                pending = launch { afterChange(network, sleep) }
            }
            sleep(POLL_MILLIS)
        }
    }

    /** Режим сессии — по памяти режима для нынешней сети (D-64): белый список или неизвестен. */
    private fun retake(reason: String) {
        val regime = check.regime()
        retaken(regime)
        log.info("network_regime_retaken", "reason" to Safe(reason), "class" to (regime?.restriction ?: RestrictionClass.UNKNOWN))
    }

    companion object {
        /** Сеть — из `/proc/net/route` или таблицы маршрутов Windows: раз в 2 с — дёшево и быстро для смены Wi-Fi. */
        const val POLL_MILLIS: Long = 2_000
        const val BUSY_POLL_MILLIS: Long = 500
    }
}
