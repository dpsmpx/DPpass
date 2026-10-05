package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
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
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.simulation.PathClass
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import kotlinx.coroutines.withTimeoutOrNull

/**
 * Проверка здоровья запущенного кандидата: идёт ли **полезная нагрузка**
 * через туннель, а не только «рукопожатие прошло» (L7 —
 * «подключено, но данных нет»).
 */
fun interface HealthChecker {
    suspend fun check(session: EngineSession, profile: ServerProfile): Outcome<Unit>
}

/** Здоровье по модели сети — для тестов и `cli`. */
class SimulatedHealthChecker(private val network: SimulatedNetwork) : HealthChecker {
    override suspend fun check(session: EngineSession, profile: ServerProfile): Outcome<Unit> {
        val path = when (profile.transportClass) {
            TransportClass.TCP_STREAM -> PathClass.TCP_STREAM
            TransportClass.HTTP_CDN -> PathClass.HTTP_CDN
            TransportClass.UDP_QUIC -> PathClass.UDP_QUIC
        }
        return when (network.candidatePath(path, profile.endpoint.toString(), profile.hints.reachableUnderAllowlist)) {
            ProbeOutcome.SUCCESS -> Outcome.Success(Unit)
            ProbeOutcome.STALLED -> Outcome.failure(DiagCode.PAYLOAD_STALLED, "соединение установлено, но данные не идут")
            ProbeOutcome.RESET -> Outcome.failure(DiagCode.TLS_HANDSHAKE_FAILED, "соединение сброшено при рукопожатии")
            else -> Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "сервер недоступен из этой сети")
        }
    }
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
    private val pause: suspend (Long) -> Unit,
) {
    suspend fun connect(ir: ConfigIr, plan: ConnectionPlan, tun: TunInput?): ConnectionReport {
        if (plan.attempts.isEmpty()) {
            val d = Diagnostic.error(plan.verdict ?: DiagCode.NO_VIABLE_CANDIDATE, plan.verdictMessage ?: "нет кандидатов")
            log.diagnostic(d)
            return ConnectionReport.Failed(d, emptyList(), plan)
        }
        val records = mutableListOf<AttemptRecord>()
        for ((n, attempt) in plan.attempts.withIndex()) {
            if (n > 0) pause(policy.pacingMillis)
            val p = attempt.profile
            log.info("attempt", "profile" to Safe(p.id.value), "class" to p.transportClass, "reasons" to Safe(attempt.reasons.joinToString("; ")))
            val failure = when (val t = tryOne(ir, p, tun)) {
                is Try.Ok -> {
                    book.recordSuccess(p.id, clock.nowMillis())
                    records += AttemptRecord(p.id, attempt.reasons, true, null)
                    return ConnectionReport.Connected(p.id, t.session, records, plan)
                }
                is Try.Fail -> t.reason
            }
            book.recordFailure(p.id, failure.code, clock.nowMillis())
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

    private sealed interface Try {
        data class Ok(val session: EngineSession) : Try
        data class Fail(val reason: Diagnostic) : Try
    }

    private suspend fun tryOne(ir: ConfigIr, p: ServerProfile, tun: TunInput?): Try {
        val compiled = when (val c = compiler.compile(ir, CompilePlan(p.id, tun != null))) {
            is Outcome.Failure -> return Try.Fail(c.errors.first())
            is Outcome.Success -> c.value
        }
        (engine.validate(compiled) as? Outcome.Failure)?.let { return Try.Fail(it.errors.first()) }
        val session = when (val s = engine.start(compiled, tun)) {
            is Outcome.Failure -> return Try.Fail(s.errors.first())
            is Outcome.Success -> s.value
        }
        val result = withTimeoutOrNull(policy.healthTimeoutMillis) { health.check(session, p) }
            ?: Outcome.failure(DiagCode.HEALTH_CHECK_FAILED, "проверка здоровья не уложилась в ${policy.healthTimeoutMillis} мс")
        if (result is Outcome.Failure) {
            session.stop()
            return Try.Fail(result.errors.first())
        }
        // Успех с оговоркой (например, здоровье не проверено, D-32) — в журнал, а не мимо.
        result.diagnostics.forEach(log::diagnostic)
        return Try.Ok(session)
    }
}
