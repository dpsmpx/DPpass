package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.connection.SessionSupervisor
import com.dpsmpx.dppass.connection.StabilityObservation
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkAssessment

/**
 * Наблюдатель сеанса на ПК (D-78, к D-44 и D-58) — как у сервиса туннеля
 * Android: раз в [INTERVAL_MILLIS] проба здоровья через сервер сеанса
 * (D-32), наблюдение — в адаптивную модель. Подтверждённая деградация (череда
 * сбоев, а не один — T14) — отказ в журнал здоровья и решение ядра
 * ([DPpassCore.degraded]): переподключиться по плану, спросить о замене
 * выбранного сервера или заменить его с согласием заранее.
 *
 * Режим сети (D-64) — по проверке сети на ПК (D-79): взят при подключении
 * и заново при смене сети (D-80) — перед каждой пробой берётся нынешний.
 * Опыт — в его контекст, замена — по нему. Пока идёт проверка сети, проба
 * не начинается, а начатая не учитывается (T14).
 *
 * Сеть ПК пропала (D-115, к D-113) — это не сбой сервера: проба не делается,
 * а начатая, на которую пришлась пропажа, в модель и журнал здоровья не идёт.
 * Пропажу наблюдатель замечает за [NETWORK_POLL_MILLIS] и отдаёт сеансу
 * ([End.NetworkLost]) — тот держит туннель и ждёт сеть ([SessionRecovery]).
 */
class SessionWatch(
    private val core: DPpassCore,
    private val profileId: ProfileId,
    private val profile: ServerProfile?,
    /** Проба здоровья (D-32); блокирует поток не дольше своего срока. */
    private val probe: () -> Outcome<Unit>,
    /** Выбранный пользователем сервер (D-34). */
    private val preferred: () -> ProfileId?,
    /** «Автопереключение сервера» (D-58): согласие заранее. */
    private val autoSwitch: () -> Boolean,
    /** Серверы, о которых пользователь ответил «Остаться». */
    private val declined: () -> Set<ProfileId>,
    /** Режим сессии (D-64): белый список по свежей проверке; null — неизвестен. */
    private val regime: () -> NetworkAssessment? = { null },
    /** Идёт проверка сети (D-79): проба мерила бы её, а не сервер. */
    private val quiet: () -> Boolean = { false },
    private val monotonic: () -> Long = Clock.MONOTONIC::nowMillis,
    /** Есть ли сеть ПК под туннелем (D-115): маршрут по умолчанию мимо него. */
    private val networkUp: () -> Boolean = { true },
) {
    /** Чем кончилось наблюдение. */
    sealed interface End {
        /** Деградация подтверждена, ядро решило, что делать (D-58). */
        data class Degraded(val decision: Degradation) : End

        /** Сеть ПК пропала (D-115): не отказ сервера — держать туннель и ждать сеть. */
        data object NetworkLost : End
    }

    private var applied: NetworkAssessment? = regime()
    private val supervisor: SessionSupervisor = core.supervisor(profileId, applied)
    private var samples = 0
    private var lastFailure: Diagnostic? = null

    /** Одна проба. null — держаться; иначе деградация подтверждена, и ядро решило, что делать. */
    fun step(): Degradation? {
        if (quiet()) {
            core.log.info("adaptive_probe_skipped", "profile" to Safe(profileId.value), "reason" to Safe("measurement"))
            return null
        }
        // Сети нет (D-115): проба мерила бы её отсутствие, а не сервер.
        if (!networkUp()) {
            core.log.info("adaptive_probe_skipped", "profile" to Safe(profileId.value), "reason" to Safe("network_down"))
            return null
        }
        val started = monotonic()
        val result = probe()
        val elapsed = (monotonic() - started).coerceAtLeast(1)
        val failed = result is Outcome.Failure
        // Сеть пропала, пока шла проба: исход — не про сервер, в модель и журнал здоровья не идёт (D-115).
        if (!networkUp()) {
            core.log.info("adaptive_probe_discarded", "profile" to Safe(profileId.value), "ok" to !failed, "reason" to Safe("network_down"))
            return null
        }
        // Проверка началась, пока шла проба: исход — не про сервер, в модель не идёт.
        if (quiet()) {
            core.log.info("adaptive_probe_discarded", "profile" to Safe(profileId.value), "ok" to !failed, "elapsed_ms" to elapsed)
            return null
        }
        val stalled = failed && result.errors.any { it.code == DiagCode.PAYLOAD_STALLED }
        // Режим сессии взят заново (смена сети, D-80): следующие наблюдения — в его контекст.
        val now = regime()
        if (now !== applied) {
            supervisor.changeContext(now)
            applied = now
        }
        val decision = supervisor.onObservation(
            StabilityObservation(success = !failed, rttMillis = elapsed, stalled = stalled, timestampMillis = core.clock.nowMillis()),
            profile,
            now,
        )
        if (failed) {
            val reason = result.errors.first()
            lastFailure = reason
            core.log.warning(
                "adaptive_probe_failed",
                *listOfNotNull(
                    "profile" to Safe(profileId.value),
                    "elapsed_ms" to elapsed,
                    "code" to Safe(reason.code.name),
                    "reason" to reason.message,
                    reason.causes.firstNotNullOfOrNull { it.error?.message }?.let { "error" to it },
                ).toTypedArray(),
            )
        }
        if (++samples % PERSIST_EVERY_SAMPLES == 0 || decision == SessionSupervisor.Decision.RECONNECT) core.persistStability()
        if (decision != SessionSupervisor.Decision.RECONNECT) return null
        core.log.warning("adaptive_reconnect", "profile" to Safe(profileId.value))
        // Деградация подтверждена скачком задержки, без проваленной пробы — общая причина.
        val reason = lastFailure ?: Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "пробы через сервер раз за разом отвечают с перебоями")
        return core.degraded(profileId, reason, preferred(), autoSwitch(), declined(), applied)
    }

    /**
     * Пробы раз в [INTERVAL_MILLIS], пока деградация не подтвердится; сеть — раз в
     * [NETWORK_POLL_MILLIS]: пропала — сразу [End.NetworkLost], не дожидаясь пробы.
     * Отмена — остановка сеанса.
     */
    suspend fun run(sleep: suspend (Long) -> Unit): End {
        var left = INTERVAL_MILLIS
        while (true) {
            val nap = minOf(NETWORK_POLL_MILLIS, left)
            sleep(nap)
            left -= nap
            if (!networkUp()) {
                core.log.info("adaptive_network_lost", "profile" to Safe(profileId.value))
                return End.NetworkLost
            }
            if (left > 0) continue
            left = INTERVAL_MILLIS
            step()?.let { return End.Degraded(it) }
        }
    }

    companion object {
        /** Как у Android (D-44): проба раз в 15 с. */
        const val INTERVAL_MILLIS: Long = 15_000

        /** Сеть ПК — раз в 2 с (D-115): пропажа видна в окне сразу, а не через пробу. */
        const val NETWORK_POLL_MILLIS: Long = 2_000

        /** Модель — на диск раз в столько проб, чтобы опыт пережил выход. */
        const val PERSIST_EVERY_SAMPLES: Int = 8
    }
}
