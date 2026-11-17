package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CompilePlan
import com.dpsmpx.dppass.engine.DesyncCounters
import com.dpsmpx.dppass.engine.DesyncTrick
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.ProxyEngine

/** Вариант попытки замера А/Б (D-116, `docs/research/FAKE_PACKETS.md`, §6.2). */
sealed interface TrialVariant {
    /** Для журнала и окна: вид, без адресов. */
    val label: String

    /** Без приёма. */
    data object Plain : TrialVariant {
        override val label: String = "plain"
    }

    /** Разбиение ClientHello (D-68). */
    data object Split : TrialVariant {
        override val label: String = "split"
    }

    /** Приём эксперимента: перестановка или подделка с TTL. */
    data class Trick(val trick: DesyncTrick) : TrialVariant {
        override val label: String = trick.label
    }
}

/**
 * Что мерить (D-116): подделка — с TTL от [ttlFrom] до [ttlTo] (подбор от
 * малого к большему, §6.2), [attempts] попыток каждого варианта, пауза
 * [pauseMillis] между попытками (D-14: без залпов).
 */
data class TrialSettings(
    val ttlFrom: Int = 3,
    val ttlTo: Int = 8,
    val attempts: Int = 10,
    val pauseMillis: Long = 3_000,
) {
    /** Что не так с настройками — для окна; null — годятся. */
    fun problem(): String? = when {
        ttlFrom !in DesyncTrick.MIN_TTL..DesyncTrick.MAX_TTL || ttlTo !in DesyncTrick.MIN_TTL..DesyncTrick.MAX_TTL ->
            "TTL — от ${DesyncTrick.MIN_TTL} до ${DesyncTrick.MAX_TTL}"
        ttlFrom > ttlTo -> "начальный TTL больше конечного"
        ttlTo - ttlFrom + 1 > MAX_TTL_STEPS -> "не больше $MAX_TTL_STEPS значений TTL за замер"
        attempts !in 1..MAX_ATTEMPTS -> "попыток каждого варианта — от 1 до $MAX_ATTEMPTS"
        pauseMillis < MIN_PAUSE_MILLIS -> "пауза между попытками — не меньше ${MIN_PAUSE_MILLIS / 1000} с (D-14)"
        else -> null
    }

    /** Варианты по §6.2: без приёма, разбиение, перестановка, подделка с каждым TTL. */
    fun variants(): List<TrialVariant> = listOf(TrialVariant.Plain, TrialVariant.Split, TrialVariant.Trick(DesyncTrick.Disorder)) +
        (ttlFrom..ttlTo).map { TrialVariant.Trick(DesyncTrick.Fake(it)) }

    companion object {
        const val MAX_TTL_STEPS: Int = 16
        const val MAX_ATTEMPTS: Int = 20
        const val MIN_PAUSE_MILLIS: Long = 1_000
    }
}

/**
 * Попытка: [ok] — проба здоровья через сервер прошла (D-32); [code] — вид
 * отказа; [applied] — мост сделал приём (null — у варианта приёма нет).
 */
data class TrialAttempt(
    val variant: String,
    val n: Int,
    val ok: Boolean,
    val elapsedMillis: Long,
    val code: DiagCode?,
    val applied: Boolean?,
)

/** Итог варианта: успехов из [total], медиана времени удачных, виды отказов, сколько раз приёма не было. */
data class TrialSummary(
    val variant: String,
    val ok: Int,
    val total: Int,
    val medianMillis: Long?,
    val failures: Map<DiagCode, Int>,
    val notApplied: Int,
)

data class TrialReport(val attempts: List<TrialAttempt>, val summaries: List<TrialSummary>)

/**
 * Замер А/Б эксперимента с началом соединения (D-116, вариант «а»
 * `FAKE_PACKETS.md`, методика — §6.2). Только к своему серверу, только при
 * выключенном туннеле: ядро на каждую попытку — заново, без TUN, с одним этим
 * сервером; попытка — проба здоровья через него (D-32). Варианты — в
 * случайном порядке (криптографическая случайность или зерно теста, D-21),
 * между попытками — пауза. В журнал — вид, исход, время и вид отказа, без
 * адресов и имён (D-26); итог — наблюдение для одной сети на дату, а не
 * «работает» (D-13).
 */
class DesyncTrial(
    private val compiler: BackendCompiler,
    private val engine: ProxyEngine,
    private val clock: Clock,
    private val log: Logger,
    /** Случайный индекс `0 until n` для порядка попыток: SecureRandom, в тестах — зерно (D-21). */
    private val pick: (Int) -> Int,
    /** Счётчики приёма моста: сверка, что приём действительно был. */
    private val counters: () -> DesyncCounters? = engine::desyncCounters,
) {
    /** Порядок попыток: каждый вариант [TrialSettings.attempts] раз, вперемешку. */
    fun schedule(settings: TrialSettings): List<TrialVariant> {
        val order = settings.variants().flatMap { v -> List(settings.attempts) { v } }.toMutableList()
        // Тасование Фишера — Йетса.
        for (i in order.lastIndex downTo 1) {
            val j = pick(i + 1)
            order[i] = order[j].also { order[j] = order[i] }
        }
        return order
    }

    /**
     * Замер на [profileId] из [ir]. [context] — тип сети и режим (D-64) для
     * журнала; [progress] — сделано из всего. Отказ до первой попытки —
     * причина (сервер без TLS поверх TCP, неверные настройки).
     */
    suspend fun run(
        ir: ConfigIr,
        profileId: ProfileId,
        checker: HealthChecker,
        settings: TrialSettings,
        context: List<Pair<String, Any>> = emptyList(),
        pause: suspend (Long) -> Unit,
        progress: (Int, Int) -> Unit = { _, _ -> },
    ): Outcome<TrialReport> {
        settings.problem()?.let { return Outcome.failure(DiagCode.CAPABILITY_FEATURE_UNSUPPORTED, "замер не начат: $it") }
        val profile = ir.profiles.firstOrNull { it.id == profileId }
            ?: return Outcome.failure(DiagCode.PROFILES_EMPTY, "сервера для замера нет в действующей конфигурации")
        // Приёму нужен TLS поверх TCP: компилятор говорит, что применить нечего, — замер бессмыслен.
        when (val probe = compiler.compile(ir, CompilePlan(profileId, withTun = false, desync = DesyncTrick.Disorder))) {
            is Outcome.Failure -> return probe
            is Outcome.Success -> probe.diagnostics.firstOrNull { it.code == DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED }?.let {
                return Outcome.failure(Diagnostic.error(it.code, "замер не начат: ${it.message}", it.path))
            }
        }
        val order = schedule(settings)
        log.info("desync_trial_started", *(listOf("variants" to settings.variants().size, "attempts" to order.size) + context).toTypedArray())
        val done = mutableListOf<TrialAttempt>()
        val seen = mutableMapOf<String, Int>()
        for ((i, v) in order.withIndex()) {
            if (i > 0) pause(settings.pauseMillis)
            val n = (seen[v.label] ?: 0) + 1
            seen[v.label] = n
            val a = attempt(ir, profile.id, v, n) { checker.check(it, profile) }
            log.info(
                "desync_trial",
                "variant" to Safe(a.variant),
                "n" to a.n,
                "ok" to a.ok,
                "elapsed_ms" to a.elapsedMillis,
                "code" to Safe(a.code?.name ?: "-"),
                "applied" to Safe(a.applied?.toString() ?: "-"),
            )
            done += a
            progress(i + 1, order.size)
        }
        val summaries = summarize(settings.variants(), done)
        for (s in summaries) {
            log.info(
                "desync_trial_summary",
                "variant" to Safe(s.variant),
                "ok" to s.ok,
                "total" to s.total,
                "median_ms" to (s.medianMillis ?: -1L),
                "not_applied" to s.notApplied,
                "failures" to Safe(s.failures.entries.joinToString(",") { "${it.key.name}:${it.value}" }.ifEmpty { "-" }),
            )
        }
        return Outcome.Success(TrialReport(done, summaries))
    }

    private suspend fun attempt(
        ir: ConfigIr,
        profileId: ProfileId,
        v: TrialVariant,
        n: Int,
        check: suspend (EngineSession) -> Outcome<Unit>,
    ): TrialAttempt {
        val trick = (v as? TrialVariant.Trick)?.trick
        val plan = CompilePlan(profileId, withTun = false, splitClientHello = v is TrialVariant.Split, desync = trick)
        val config = when (val c = compiler.compile(ir, plan)) {
            is Outcome.Failure -> return failed(v, n, 0, c.errors.first())
            is Outcome.Success -> c.value
        }
        val before = counters()
        val started = clock.nowMillis()
        val session = when (val s = engine.start(config, null)) {
            is Outcome.Failure -> return failed(v, n, clock.nowMillis() - started, s.errors.first())
            is Outcome.Success -> s.value
        }
        val result = try {
            check(session)
        } finally {
            session.stop()
        }
        val elapsed = (clock.nowMillis() - started).coerceAtLeast(0)
        val after = counters()
        val applied = if (trick == null || before == null || after == null) null else after.applied > before.applied
        return TrialAttempt(v.label, n, result is Outcome.Success, elapsed, (result as? Outcome.Failure)?.errors?.first()?.code, applied)
    }

    private fun failed(v: TrialVariant, n: Int, elapsed: Long, d: Diagnostic): TrialAttempt {
        log.diagnostic(d)
        return TrialAttempt(v.label, n, false, elapsed, d.code, if (v is TrialVariant.Trick) false else null)
    }

    companion object {
        /** Итог по вариантам — в их порядке, а не в порядке попыток. */
        fun summarize(variants: List<TrialVariant>, attempts: List<TrialAttempt>): List<TrialSummary> = variants.map { v ->
            val mine = attempts.filter { it.variant == v.label }
            val okTimes = mine.filter { it.ok }.map { it.elapsedMillis }.sorted()
            TrialSummary(
                variant = v.label,
                ok = okTimes.size,
                total = mine.size,
                medianMillis = okTimes.takeIf { it.isNotEmpty() }?.let { it[it.size / 2] },
                failures = mine.mapNotNull { it.code }.groupingBy { it }.eachCount(),
                notApplied = mine.count { it.applied == false },
            )
        }
    }
}
