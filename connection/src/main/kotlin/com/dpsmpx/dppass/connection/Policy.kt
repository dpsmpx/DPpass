package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.network.LatencyProbe
import com.dpsmpx.dppass.network.LatencyResult
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.Reachability
import com.dpsmpx.dppass.network.RestrictionClass

/**
 * Параметры политики подключения (D-15). Значения — ориентиры первой
 * версии; меняются по замерам, не наугад.
 */
data class ConnectionPolicy(
    /** Сколько кандидатов пробуется за одно подключение. */
    val maxAttempts: Int = 4,
    /** Пауза между попытками: без «залпов» (D-14). */
    val pacingMillis: Long = 2_000,
    val baseBackoffMillis: Long = 30_000,
    val maxBackoffMillis: Long = 30 * 60_000,
    val healthTimeoutMillis: Long = 10_000,
)

enum class HealthState { UNKNOWN, HEALTHY, FAILED }

data class CandidateHealth(
    val state: HealthState = HealthState.UNKNOWN,
    val consecutiveFailures: Int = 0,
    val lastFailure: DiagCode? = null,
    val backoffUntilMillis: Long = 0,
    val lastSuccessMillis: Long? = null,
)

/**
 * Журнал здоровья кандидатов: экспоненциальный backoff после отказов,
 * сброс после успеха. Детерминирован: время — снаружи. Пишет оркестратор
 * в потоке сервиса, читает и интерфейс (D-34) — доступ под замком объекта.
 */
class HealthBook(private val policy: ConnectionPolicy = ConnectionPolicy()) {
    private val map = HashMap<ProfileId, CandidateHealth>()

    @Synchronized
    fun of(id: ProfileId): CandidateHealth = map[id] ?: CandidateHealth()

    @Synchronized
    fun recordSuccess(id: ProfileId, now: Long) {
        map[id] = CandidateHealth(HealthState.HEALTHY, 0, null, 0, now)
    }

    /** Кандидат, который последним реально передал данные (а не просто был активирован). */
    @Synchronized
    fun lastGood(): ProfileId? = map.entries
        .filter { it.value.state == HealthState.HEALTHY && it.value.lastSuccessMillis != null }
        .maxByOrNull { it.value.lastSuccessMillis!! }?.key

    @Synchronized
    fun recordFailure(id: ProfileId, code: DiagCode, now: Long) {
        val prev = of(id)
        val n = prev.consecutiveFailures + 1
        val backoff = (policy.baseBackoffMillis shl (n - 1).coerceAtMost(20)).coerceAtMost(policy.maxBackoffMillis)
        map[id] = prev.copy(state = HealthState.FAILED, consecutiveFailures = n, lastFailure = code, backoffUntilMillis = now + backoff)
    }
}

/**
 * Задержка до серверов (D-41): последний замер каждого, только в памяти
 * процесса. Пишет замер по действию пользователя, читают интерфейс и
 * план — доступ под замком объекта.
 */
class LatencyBook {
    private val map = HashMap<ProfileId, LatencyResult>()

    @Synchronized
    fun of(id: ProfileId): LatencyResult? = map[id]

    /** Задержка, если замер удался (для плана); иначе null. */
    @Synchronized
    fun millis(id: ProfileId): Long? = (map[id] as? LatencyResult.Measured)?.millis

    @Synchronized
    fun record(id: ProfileId, result: LatencyResult) {
        map[id] = result
    }

    @Synchronized
    fun clear() {
        map.clear()
    }

    /**
     * Замер серверов по одному с паузой (D-14, D-41: без залпов); UDP
     * (Hysteria2) — не мерится. [onEach] — после каждого: интерфейс
     * показывает итоги по мере появления.
     */
    suspend fun measureAll(
        profiles: List<ServerProfile>,
        probe: LatencyProbe,
        pause: suspend (Long) -> Unit,
        timeoutMillis: Int = TIMEOUT_MILLIS,
        onEach: (ProfileId, LatencyResult) -> Unit = { _, _ -> },
    ) {
        for ((i, p) in profiles.take(MAX_PER_RUN).withIndex()) {
            val r = if (p.transportClass == TransportClass.UDP_QUIC) {
                LatencyResult.NotTcp
            } else {
                if (i > 0) pause(PACING_MILLIS)
                probe.measure(p.endpoint.host, p.endpoint.port, timeoutMillis)
            }
            record(p.id, r)
            onEach(p.id, r)
        }
    }

    companion object {
        const val TIMEOUT_MILLIS: Int = 3_000
        const val PACING_MILLIS: Long = 150
        const val MAX_PER_RUN: Int = 128
    }
}

/** Попытка в плане — всегда с причинами, почему она здесь и на этом месте. */
data class PlannedAttempt(val profile: ServerProfile, val reasons: List<String>)

data class Exclusion(val profileId: ProfileId, val reason: String)

data class ConnectionPlan(
    val attempts: List<PlannedAttempt>,
    val excluded: List<Exclusion>,
    /** Если план пуст — почему (для пользователя). */
    val verdict: DiagCode?,
    val verdictMessage: String?,
)

/**
 * Упорядоченный, ограниченный, объяснимый план кандидатов (D-15).
 * Никакой случайности: одинаковые вход и время дают одинаковый план.
 *
 * Шаги: сеть (нет сети, страница входа) → возможности ядра → пригодность
 * для класса сети (белый список, UDP) → backoff → порядок
 * (выбор пользователя, last-known-good, здоровье, класс транспорта,
 * приоритет, задержка (D-41), id) → разнообразие классов → предел попыток. Выбор
 * пользователя (D-34) — первая попытка; остальные — запасные по D-15.
 *
 * Режим сети по свежей проверке (D-64) — мягкий: никого не исключает, а
 * под белым списком ставит опыт под ним ([StabilityModel] в контексте
 * белого списка) выше «последнего удачного» и здоровья — они общие для
 * всех режимов, а под списком закрыто то, что в обычной сети работает.
 */
object CandidatePlanner {
    fun plan(
        ir: ConfigIr,
        caps: EngineCapabilities,
        assessment: NetworkAssessment?,
        health: HealthBook,
        lastKnownGood: ProfileId?,
        nowMillis: Long,
        policy: ConnectionPolicy = ConnectionPolicy(),
        /** Выбор пользователя (D-34): первым; пауза после отказа для него не действует. */
        preferred: ProfileId? = null,
        /** Задержка по замеру (D-41): порядок среди равных по здоровью, классу и приоритету. */
        latency: (ProfileId) -> Long? = { null },
        /** Выученная устойчивость (D-44): порядок среди годных; жёсткие исключения не трогает. */
        stability: StabilityModel? = null,
        /** Режим сети по свежей проверке (D-64): только порядок и контекст опыта, без исключений. */
        regime: NetworkAssessment? = null,
    ): ConnectionPlan {
        when (assessment?.restriction) {
            RestrictionClass.OFFLINE -> return ConnectionPlan(emptyList(), emptyList(), DiagCode.NETWORK_OFFLINE, "нет сети — попытки не делаются")
            RestrictionClass.CAPTIVE -> return ConnectionPlan(
                emptyList(), emptyList(), DiagCode.ENDPOINT_UNREACHABLE, "сеть требует входа на странице оператора (captive portal)",
            )
            else -> Unit
        }
        val excluded = mutableListOf<Exclusion>()
        val viable = mutableListOf<ServerProfile>()
        for ((i, p) in ir.profiles.withIndex()) {
            val problems = CapabilityChecker.checkProfile(p, caps, "$.profiles[$i]").filter { it.isError }
            when {
                problems.isNotEmpty() -> excluded += Exclusion(p.id, "ядро ${caps.backendId}: ${problems.first().message}")
                assessment?.restriction == RestrictionClass.ALLOWLIST_LIKE && !p.hints.reachableUnderAllowlist ->
                    excluded += Exclusion(p.id, "сеть похожа на белый список, а кандидат не отмечен как доступный из неё")
                assessment?.udp == Reachability.BLOCKED && p.transportClass == TransportClass.UDP_QUIC ->
                    excluded += Exclusion(p.id, "UDP в этой сети не проходит, а кандидат — UDP/QUIC")
                p.id != preferred && health.of(p.id).backoffUntilMillis > nowMillis -> {
                    val left = (health.of(p.id).backoffUntilMillis - nowMillis + 999) / 1000
                    excluded += Exclusion(p.id, "пауза после отказа ${health.of(p.id).lastFailure}: ещё $left с")
                }
                else -> viable += p
            }
        }
        if (viable.isEmpty()) {
            val allowlist = assessment?.restriction == RestrictionClass.ALLOWLIST_LIKE
            val msg = if (allowlist) {
                "сеть пропускает только разрешённые адреса; нужен кандидат, доступный из этой сети — клиент не может создать путь, которого нет (D-13)"
            } else {
                "нет кандидатов, пригодных сейчас"
            }
            return ConnectionPlan(emptyList(), excluded, DiagCode.NO_VIABLE_CANDIDATE, msg)
        }
        // Штраф TCP-потока — только когда путь наружу есть, но TLS или крупные передачи режутся;
        // при белом списке зарубежное недоступно целиком, и штраф ничего не значит.
        val tcpPenalized = assessment != null && assessment.restriction != RestrictionClass.ALLOWLIST_LIKE &&
            (assessment.tls == Reachability.BLOCKED || assessment.tls == Reachability.DEGRADED || assessment.bulk == Reachability.DEGRADED)

        fun healthRank(p: ServerProfile) = when (health.of(p.id).state) {
            HealthState.HEALTHY -> 0
            HealthState.UNKNOWN -> 1
            HealthState.FAILED -> 2
        }
        fun classPenalty(p: ServerProfile) = if (tcpPenalized && p.transportClass == TransportClass.TCP_STREAM) 1 else 0

        // Контекст опыта: оценка, если она есть, иначе мягкий режим (D-64).
        val soft = assessment ?: regime
        val underAllowlist = soft?.restriction == RestrictionClass.ALLOWLIST_LIKE

        // Выученная устойчивость (D-44): выше — раньше. Квантуется до сотых,
        // чтобы порядок был детерминирован и мелкий шум не правил план.
        // Нет модели — ноль у всех: порядок как прежде (существующие тесты).
        fun stabilityRank(p: ServerProfile) = if (stability == null) 0 else -(stability.score(p, soft) * 100).toInt()

        // Под белым списком опыт под ним — выше «последнего удачного» и здоровья (D-64).
        fun allowlistRank(p: ServerProfile) = if (underAllowlist) stabilityRank(p) else 0

        val sorted = viable.sortedWith(
            compareBy<ServerProfile>(
                { if (it.id == preferred) 0 else 1 },
                { allowlistRank(it) },
                { if (it.id == lastKnownGood) 0 else 1 },
                { healthRank(it) },
                { stabilityRank(it) },
                { classPenalty(it) },
                { -it.hints.priority },
                // Неизмеренные — после измеренных; тайм-аут — как неизмеренный, а не как отказ (D-41).
                { latency(it.id) ?: Long.MAX_VALUE },
                { it.id.value },
            ),
        )
        // Разнообразие: следующей идёт кандидат другого класса транспорта, если он не хуже по здоровью.
        val ordered = mutableListOf<PlannedAttempt>()
        val pool = sorted.toMutableList()
        while (pool.isNotEmpty()) {
            val prevClass = ordered.lastOrNull()?.profile?.transportClass
            val head = pool.first()
            // Выбор пользователя — всегда первая попытка, разнообразие классов его не сдвигает.
            val pick = if (prevClass != null && head.transportClass == prevClass && head.id != preferred) {
                pool.firstOrNull { it.transportClass != prevClass && healthRank(it) <= healthRank(head) } ?: head
            } else {
                head
            }
            pool.remove(pick)
            val reasons = mutableListOf<String>()
            if (pick.id == preferred) reasons += "выбран пользователем"
            if (pick.id == lastKnownGood) reasons += "последний удачный кандидат"
            val h = health.of(pick.id)
            when (h.state) {
                HealthState.HEALTHY -> reasons += "был здоров"
                HealthState.UNKNOWN -> reasons += "ещё не проверялся"
                // На паузе в плане только выбор пользователя: пауза ему не мешает, но
                // и «истекла» о ней не сказать (журнал 19.10.2026: «истекла» через 22 с).
                HealthState.FAILED -> reasons += if (h.backoffUntilMillis > nowMillis) {
                    "отказывал недавно: пауза ещё ${(h.backoffUntilMillis - nowMillis + 999) / 1000} с, но выбран пользователем"
                } else {
                    "отказывал раньше, пауза истекла"
                }
            }
            if (classPenalty(pick) > 0) reasons += "TCP-поток ниже: в этой сети режутся TLS или крупные передачи"
            if (pick !== head) reasons += "другой класс транспорта, чем у предыдущей попытки"
            if (pick.hints.priority != 0) reasons += "приоритет ${pick.hints.priority}"
            latency(pick.id)?.let { reasons += "задержка $it мс" }
            if (underAllowlist && stability != null) reasons += allowlistReason(stability.stats(pick.id, NetworkContext.of(soft)))
            stability?.let { reasons += "устойчивость ${(it.score(pick, soft) * 100).toInt()}%" }
            reasons += "класс ${pick.transportClass}"
            ordered += PlannedAttempt(pick, reasons)
        }
        val attempts = ordered.take(policy.maxAttempts)
        excluded += ordered.drop(policy.maxAttempts).map { Exclusion(it.profile.id, "за пределом ${policy.maxAttempts} попыток на подключение") }
        return ConnectionPlan(attempts, excluded, null, null)
    }

    /** Что известно о кандидате под белым списком (D-64) — причина в плане. */
    private fun allowlistReason(s: StabilityStats): String = when {
        !s.hasObservation -> "под белым списком ещё не пробовался"
        s.reliabilityMean >= StabilityStats.NEUTRAL -> "под белым списком работал"
        else -> "под белым списком отказывал"
    }
}
