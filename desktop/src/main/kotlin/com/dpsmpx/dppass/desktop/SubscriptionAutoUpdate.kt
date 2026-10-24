package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.SubscriptionRun
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Автообновление подписок на ПК (D-77, к D-39), пока открыто окно: процесс
 * DPpass живёт только с ним (D-74). Пора ли — решает ядро
 * (`SubscriptionService.refreshDue`, `UpdateSchedule`): только применённая
 * подписка по адресу, по её интервалу; после отказа — не раньше чем через
 * 30 минут.
 *
 * Туннель поднят — новые серверы активированы (D-07); переподключение —
 * только если подключённого сервера больше нет или он изменился.
 */
class SubscriptionAutoUpdate(
    private val core: DPpassCore,
    private val fetcher: SubscriptionFetcher,
    private val version: String,
    /** Подключённый сервер; null — туннеля нет. */
    private val connected: () -> ProfileId?,
    /** Переподключить к новым серверам. */
    private val reconnect: () -> Unit,
    /** Подписка проверена: окну перерисовать списки. */
    private val changed: () -> Unit,
) {
    /** Одна проверка: обновить, если пора. null — обновлять было нечего или не прочитать подписки. */
    suspend fun runOnce(): SubscriptionRun? {
        val r = withContext(Dispatchers.IO) { core.subscriptions.refreshDue(fetcher, version) } ?: return null
        val run = when (r) {
            is Outcome.Failure -> {
                r.errors.forEach(core.log::diagnostic)
                return null
            }
            is Outcome.Success -> r.value
        }
        core.log.info("subscription_auto_update", "applied" to run.applied, "update" to Safe(run.update::class.simpleName ?: "?"))
        // Окно журнала — главное место причин на ПК: отказ загрузки или активации — туда же (D-22).
        run.diagnostics.filter { it.isError }.forEach(core.log::diagnostic)
        changed()
        if (run.needsReconnect(connected())) {
            core.log.info("subscription_auto_reconnect")
            reconnect()
        }
        return run
    }

    /** Проверки до отмены [scope]: первая — через минуту после запуска, дальше — к сроку ([waitMillis]). */
    fun start(scope: CoroutineScope, sleep: suspend (Long) -> Unit = { delay(it) }): Job = scope.launch {
        sleep(FIRST_CHECK_MILLIS)
        while (isActive) {
            runOnce()
            sleep(waitMillis(core.subscriptions.nextDueMillis()))
        }
    }

    companion object {
        /** Сеть и подключение после запуска успевают подняться. */
        const val FIRST_CHECK_MILLIS: Long = 60_000

        const val MIN_WAIT_MILLIS: Long = 60_000

        /** Не дольше часа: подписку могли применить, а интервал — сменить. */
        const val MAX_WAIT_MILLIS: Long = 60 * 60_000

        /** До срока обновления ([nextDue], мс; null — автообновления нет), но не меньше минуты и не больше часа. */
        fun waitMillis(nextDue: Long?): Long = (nextDue ?: MAX_WAIT_MILLIS).coerceIn(MIN_WAIT_MILLIS, MAX_WAIT_MILLIS)
    }
}
