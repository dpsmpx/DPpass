package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe

/**
 * Восстановление сеанса на ПК (D-115, к D-113 и D-111): сеть пропала или
 * сервер сеанса перестал отвечать. Туннель всё это время стоит, и трафик
 * мимо него не уходит: на Linux TUN и правила остаются, пока перезапускается
 * ядро; на Windows адаптер живёт вместе с ядром, и ядро не останавливается.
 *
 * Порядок:
 * - сети нет — ничего не пробовать и отказов не записывать: ждать её,
 *   сообщив один раз ([Events.waitingNetwork]);
 * - сеть есть — пауза ([SETTLE_MILLIS] после возвращения сети, дальше —
 *   [delayMillis]), затем проба через работающее ядро: сеть вернулась, и
 *   ядро, скорее всего, уже ходит к серверу; не прошла — перезапуск ядра тем
 *   же сервером ([restart]; на Windows его нет — только проба);
 * - не вышло [NOTIFY_AFTER] раз при живой сети — [Events.unreachable]:
 *   сообщить и предложить смену сервера, но не менять его; попытки идут
 *   дальше, пока пользователь не решит иначе.
 *
 * Чистая логика: сон, сеть, проба и перезапуск — снаружи, чтобы расписание
 * проверялось тестом (`SessionRecoveryTest`).
 */
class SessionRecovery(
    private val log: Logger,
    private val networkUp: () -> Boolean,
    /** Проба здоровья через работающее ядро (D-32); null — ядро сейчас не работает. */
    private val probe: suspend () -> Outcome<Unit>?,
    /** Перезапустить ядро тем же сервером, не снимая туннель; null — на этой платформе нельзя (Windows, D-97). */
    private val restart: (suspend () -> Outcome<Unit>)?,
    private val events: Events,
) {
    /** Что видит пользователь: окно и уведомления. */
    interface Events {
        /** Сеть пропала: трафик заблокирован, ждём её. Раз на каждую пропажу. */
        fun waitingNetwork()

        /** Сеть есть — попытка номер [attempt]. */
        fun attempting(attempt: Int)

        /** Попытка не удалась при живой сети. */
        fun failed(reason: Diagnostic, attempts: Int)

        /** [NOTIFY_AFTER] неудач подряд при живой сети: сообщить и предложить смену сервера. */
        fun unreachable(reason: Diagnostic, attempts: Int)
    }

    /**
     * До восстановления; отмена — отключение или выбор пользователя.
     * [degraded] — наблюдатель уже подтвердил сбой сервера при живой сети
     * (D-58): ядро не справилось, и первая попытка — сразу перезапуск, без
     * паузы и пробы (где перезапуска нет — сразу проба). null — пропала сеть. [failedBefore] — сколько попыток уже
     * не удалось до вызова (перезапуск по кнопке только что не вышел): следующая —
     * по расписанию, а не сразу.
     */
    suspend fun run(sleep: suspend (Long) -> Unit, degraded: Diagnostic? = null, failedBefore: Int = 0) {
        var failed = failedBefore
        var down = false
        var settle = degraded == null
        // Без перезапуска (Windows) попытка — только проба: её не пропускать.
        var skipProbe = degraded != null && restart != null
        var last: Diagnostic? = degraded
        while (true) {
            if (!networkUp()) {
                if (!down) {
                    log.info("recovery_waiting_network")
                    events.waitingNetwork()
                }
                down = true
                settle = true
                skipProbe = false
                sleep(NETWORK_POLL_MILLIS)
                continue
            }
            if (down) {
                log.info("network_restored")
                down = false
            }
            val wait = when {
                settle -> SETTLE_MILLIS
                failed == 0 -> 0L
                else -> delayMillis(failed - 1)
            }
            settle = false
            if (wait > 0) sleep(wait)
            // Сеть успела пропасть за паузу — снова ждать её, а не пробовать вхолостую.
            if (!networkUp()) continue
            val attempt = failed + 1
            events.attempting(attempt)
            log.info("recovery_attempt", "n" to attempt)
            if (!skipProbe) {
                when (val p = probe()) {
                    is Outcome.Success -> return done(attempt, "probe")
                    is Outcome.Failure -> last = p.errors.first()
                    null -> Unit
                }
                // Сеть пропала во время пробы: исход — про сеть, не про сервер.
                if (!networkUp()) continue
            }
            skipProbe = false
            when (val r = restart?.invoke()) {
                is Outcome.Success -> return done(attempt, "restart")
                is Outcome.Failure -> last = r.errors.first()
                null -> Unit
            }
            if (!networkUp()) continue
            failed++
            val reason = last ?: Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "сервер не ответил на пробу через туннель")
            log.warning("recovery_failed", "n" to failed, "code" to Safe(reason.code.name), "reason" to reason.message)
            events.failed(reason, failed)
            if (failed == NOTIFY_AFTER) events.unreachable(reason, failed)
        }
    }

    private fun done(attempts: Int, by: String) {
        log.info("recovery_done", "attempts" to attempts, "by" to Safe(by))
    }

    companion object {
        /** Пауза после возвращения сети: Wi-Fi «мигает», переподключаться на первой секунде рано (как на Android, D-113). */
        const val SETTLE_MILLIS: Long = 3_000

        /** Как часто смотреть, вернулась ли сеть, пока её нет. */
        const val NETWORK_POLL_MILLIS: Long = 2_000

        /** После стольких неудач при живой сети — сообщение с предложением сменить сервер. */
        const val NOTIFY_AFTER: Int = 3

        private const val FIRST_MILLIS = 5_000L
        private const val MAX_MILLIS = 60_000L

        /** Пауза перед попыткой после [failed] + 1 неудач: 5, 10, 20, 40 с, дальше — раз в минуту. */
        fun delayMillis(failed: Int): Long = (FIRST_MILLIS shl failed.coerceIn(0, 6)).coerceAtMost(MAX_MILLIS)
    }
}

/**
 * Закрепление сервера сеанса (D-115, как D-113 на Android) — чистая логика для
 * [DesktopSession]: автопереключение выключено — сеанс держит выбранный
 * пользователем сервер, а при «Автоматически» — тот, к которому подключился.
 */
object ServerPin {
    /** Сервер, к которому подключились при «Автоматически»; [selectedAt] — выбор в тот момент: сменился — закрепление не действует. */
    data class Pin(val profile: ProfileId, val selectedAt: ProfileId?)

    /**
     * Сервер, который сеанс обязан держать; null — переключение разрешено
     * ([autoSwitch]) или держать пока нечего. Выбор, которого нет среди
     * [present] (подписка обновилась), не действует — как на экране серверов.
     */
    fun target(autoSwitch: Boolean, selected: ProfileId?, pin: Pin?, present: Collection<ProfileId>): ProfileId? {
        if (autoSwitch) return null
        selected?.takeIf { it in present }?.let { return it }
        return pin?.takeIf { it.selectedAt == selected && it.profile in present }?.profile
    }
}
