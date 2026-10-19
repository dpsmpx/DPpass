package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.TunInput
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Проверка здоровья запущенного кандидата: идёт ли **полезная нагрузка**
 * через туннель, а не только «рукопожатие прошло» (L7 —
 * «подключено, но данных нет»).
 */
fun interface HealthChecker {
    suspend fun check(session: EngineSession, profile: ServerProfile): Outcome<Unit>
}

data class AttemptRecord(
    val profileId: ProfileId,
    val reasons: List<String>,
    val ok: Boolean,
    val failure: Diagnostic?,
)

sealed interface ConnectionReport {
    val attempts: List<AttemptRecord>
    val plan: ConnectionPlan

    data class Connected(
        val profileId: ProfileId,
        val session: EngineSession,
        override val attempts: List<AttemptRecord>,
        override val plan: ConnectionPlan,
        /**
         * Раздача (D-51) не поднялась: ядро с её входами не запустилось
         * (адрес пропал, порт занят), без них — запустилось. Туннель работает
         * без раздачи; null — раздача поднята или не просилась.
         */
        val shareRefused: Diagnostic? = null,
    ) : ConnectionReport

    data class Failed(val reason: Diagnostic, override val attempts: List<AttemptRecord>, override val plan: ConnectionPlan) : ConnectionReport
}

/**
 * Выполнение плана (D-15): кандидаты по порядку, с паузой между
 * попытками, ограниченное число раз. Каждая попытка записывается с
 * причиной из плана и исходом. Отказ кандидата ставит его на паузу
 * (backoff) в [HealthBook]; успех снимает паузу.
 */
class ConnectionOrchestrator(
    private val compiler: BackendCompiler,
    private val engine: ProxyEngine,
    private val health: HealthChecker,
    private val book: HealthBook,
    private val clock: Clock,
    private val log: Logger,
    private val policy: ConnectionPolicy = ConnectionPolicy(),
    /** Адаптивная модель (D-44): каждая попытка — наблюдение. */
    private val stability: StabilityModel? = null,
    private val assessment: com.dpsmpx.dppass.network.NetworkAssessment? = null,
    // pause — последним: вызывается замыкающей лямбдой у вызывающего.
    private val pause: suspend (Long) -> Unit,
) {
    private val context = NetworkContext.of(assessment)

    /**
     * [share] — раздача туннеля другим устройствам (D-51): входы ядра на
     * адресах раздачи. [splitClientHello] — разбивать ClientHello к серверу
     * (D-68), выбор пользователя.
     */
    suspend fun connect(ir: ConfigIr, plan: ConnectionPlan, tun: TunInput?, share: ShareSpec? = null, splitClientHello: Boolean = false): ConnectionReport {
        if (plan.attempts.isEmpty()) {
            val d = Diagnostic.error(plan.verdict ?: DiagCode.NO_VIABLE_CANDIDATE, plan.verdictMessage ?: "нет кандидатов")
            log.diagnostic(d)
            return ConnectionReport.Failed(d, emptyList(), plan)
        }
        val records = mutableListOf<AttemptRecord>()
        var offered = share
        var shareRefused: Diagnostic? = null
        for ((n, attempt) in plan.attempts.withIndex()) {
            if (n > 0) pause(policy.pacingMillis)
            val p = attempt.profile
            log.info("attempt", "profile" to Safe(p.id.value), "class" to p.transportClass, "reasons" to Safe(attempt.reasons.joinToString("; ")))
            val startedAt = clock.nowMillis()
            val t = tryOne(ir, p, tun, offered, splitClientHello)
            // Раздачу отверг запуск, а не сервер: следующие попытки — без неё (D-51).
            t.shareRefused?.let {
                log.diagnostic(it)
                shareRefused = it
                offered = null
            }
            val failure = when (t) {
                is Try.Ok -> {
                    book.recordSuccess(p.id, clock.nowMillis())
                    observe(p, startedAt, success = true, stalled = false)
                    records += AttemptRecord(p.id, attempt.reasons, true, null)
                    return ConnectionReport.Connected(p.id, t.session, records, plan, shareRefused)
                }
                is Try.Fail -> t.reason
            }
            book.recordFailure(p.id, failure.code, clock.nowMillis())
            observe(p, startedAt, success = false, stalled = failure.code == DiagCode.PAYLOAD_STALLED)
            log.diagnostic(failure)
            records += AttemptRecord(p.id, attempt.reasons, false, failure)
        }
        val n = plan.attempts.size
        val d = Diagnostic.error(
            DiagCode.ATTEMPTS_EXHAUSTED,
            if (n == 1) "единственный кандидат не передал данных" else "ни один из $n кандидатов не передал данных",
        )
            .copy(causes = records.mapNotNull { it.failure })
        return ConnectionReport.Failed(d, records, plan)
    }

    /** Исход попытки — наблюдение адаптивной модели (D-44); обучает и обобщение. */
    private fun observe(p: ServerProfile, startedAt: Long, success: Boolean, stalled: Boolean) {
        val model = stability ?: return
        val now = clock.nowMillis()
        model.observe(
            p.id,
            context,
            StabilityObservation(success, (now - startedAt).coerceAtLeast(1), stalled, now),
            p,
            assessment,
        )
    }

    /** [shareRefused] — раздача не поднялась, и попытка шла без неё (D-51). */
    private sealed interface Try {
        val shareRefused: Diagnostic?

        data class Ok(val session: EngineSession, override val shareRefused: Diagnostic? = null) : Try
        data class Fail(val reason: Diagnostic, override val shareRefused: Diagnostic? = null) : Try
    }

    private suspend fun tryOne(ir: ConfigIr, p: ServerProfile, tun: TunInput?, share: ShareSpec?, split: Boolean): Try {
        val compiled = when (val c = compiler.compile(ir, CompilePlan(p.id, tun != null, share, split))) {
            is Outcome.Failure -> return Try.Fail(c.errors.first())
            is Outcome.Success -> c.value
        }
        (engine.validate(compiled) as? Outcome.Failure)?.let { return Try.Fail(it.errors.first()) }
        val session = when (val s = engine.start(compiled, tun)) {
            is Outcome.Failure -> {
                val reason = s.errors.first()
                // Вход раздачи не встал (адрес пропал, порт занят — D-51): это отказ
                // запуска, а не сервера. Та же попытка без раздачи; запустилась —
                // туннель работает без неё, и сервер не наказывается.
                if (share == null || reason.code != DiagCode.BACKEND_START_FAILED) return Try.Fail(reason)
                val refused = Diagnostic.warning(DiagCode.BACKEND_START_FAILED, "раздача не поднялась: ядро с её входами не запустилось — туннель без раздачи")
                    .withCause(reason)
                return when (val t = tryOne(ir, p, tun, null, split)) {
                    is Try.Ok -> t.copy(shareRefused = refused)
                    is Try.Fail -> t.copy(shareRefused = refused)
                }
            }
            is Outcome.Success -> s.value
        }
        // Сеанс запущен и до передачи вызывающему — наш. Отмена посреди проверки
        // здоровья («Отключить», onRevoke, переподключение) иначе оставила бы ядро
        // работать: TUN уже закрыт, а вход раздачи (D-51) — открыт, со старым паролем.
        val result = try {
            withTimeoutOrNull(policy.healthTimeoutMillis) { health.check(session, p) }
                ?: Outcome.failure(DiagCode.HEALTH_CHECK_FAILED, "проверка здоровья не уложилась в ${policy.healthTimeoutMillis} мс")
        } catch (e: Throwable) {
            withContext(NonCancellable) { session.stop() }
            throw e
        }
        if (result is Outcome.Failure) {
            session.stop()
            return Try.Fail(result.errors.first())
        }
        // Успех с оговоркой (например, здоровье не проверено, D-32) — в журнал, а не мимо.
        result.diagnostics.forEach(log::diagnostic)
        return Try.Ok(session)
    }
}
