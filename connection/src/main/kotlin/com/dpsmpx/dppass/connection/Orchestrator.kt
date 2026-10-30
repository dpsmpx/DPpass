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
import com.dpsmpx.dppass.engine.LocalProxySpec
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.routing.SplitSites
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
    /** Серверы, не принявшие разбитый ClientHello (D-69): общая на процесс, у [DPpassCore]. */
    private val splitMemory: SplitMemory = SplitMemory(),
    // pause — последним: вызывается замыкающей лямбдой у вызывающего.
    private val pause: suspend (Long) -> Unit,
) {
    private val context = NetworkContext.of(assessment)

    /**
     * [share] — раздача туннеля другим устройствам (D-51): входы ядра на
     * адресах раздачи. [splitClientHello] — разбивать ClientHello к серверу
     * (D-68), выбор пользователя; сервер, который его не принял, — без
     * разбиения (D-69). [splitSites] — сайты напрямую с разбиением (D-72),
     * список пользователя; от отказа сервера не зависит. [local] —
     * локальный прокси подключения без VPN (D-95): только без [tun]; не
     * поднялся — отказ устройства, серверы не наказываются. [systemTun] —
     * TUN, который создаёт само ядро (Windows, D-97): вместо [tun], не
     * вместе с ним.
     */
    suspend fun connect(
        ir: ConfigIr,
        plan: ConnectionPlan,
        tun: TunInput?,
        share: ShareSpec? = null,
        splitClientHello: Boolean = false,
        splitSites: SplitSites = SplitSites.NONE,
        local: LocalProxySpec? = null,
        systemTun: SystemTun? = null,
    ): ConnectionReport {
        require(tun == null || systemTun == null) { "TUN платформы и TUN ядра вместе (D-97)" }
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
            var startedAt = clock.nowMillis()
            var reasons = attempt.reasons
            val remembered = splitClientHello && splitMemory.rejected(p.id)
            if (remembered) {
                log.info("client_hello_split_skipped", "profile" to Safe(p.id.value))
                reasons = reasons + SPLIT_REMEMBERED
            }
            // Раздачу отверг запуск, а не сервер: следующие попытки — без неё (D-51).
            fun refuseShare(t: Try) = t.shareRefused?.let {
                log.diagnostic(it)
                shareRefused = it
                offered = null
            }
            var t = tryOne(ir, p, tun, offered, splitClientHello && !remembered, splitSites, local, systemTun).also(::refuseShare)
            // Сервер не принял разбитый ClientHello (D-69): та же попытка без
            // разбиения, сразу; в учёт здоровья и опыта идёт только она.
            if (t is Try.Fail && t.split && SplitFallback.rejectedBy(t.reason)) {
                log.diagnostic(
                    Diagnostic.warning(DiagCode.CLIENT_HELLO_SPLIT_REJECTED, "сервер не принял ClientHello по частям — та же попытка без разбиения")
                        .withCause(t.reason),
                )
                splitMemory.reject(p.id)
                reasons = reasons + SPLIT_REJECTED
                startedAt = clock.nowMillis()
                t = tryOne(ir, p, tun, offered, false, splitSites, local, systemTun).also(::refuseShare)
            }
            val failure = when (t) {
                is Try.Ok -> {
                    book.recordSuccess(p.id, clock.nowMillis())
                    observe(p, startedAt, success = true, stalled = false)
                    records += AttemptRecord(p.id, reasons, true, null)
                    return ConnectionReport.Connected(p.id, t.session, records, plan, shareRefused)
                }
                is Try.Fail -> t.reason
            }
            // Ядро ещё держит прежний сеанс — отказ этого телефона, а не сервера:
            // следующие кандидаты упрутся в то же, а пауза наказала бы исправные
            // серверы (журнал 19.10.2026: четыре попытки подряд, все — «уже запущено»).
            if (failure.code == DiagCode.BACKEND_ALREADY_RUNNING) {
                val busy = Diagnostic.error(DiagCode.BACKEND_ALREADY_RUNNING, "ядро ещё занято прежним подключением — серверы не пробовались")
                    .withCause(failure)
                log.diagnostic(busy)
                records += AttemptRecord(p.id, reasons, false, busy)
                return ConnectionReport.Failed(busy, records, plan)
            }
            // Локальный прокси не поднялся (D-95): порт занят на этом устройстве — у
            // следующих кандидатов то же, а сервер ни при чём. Так же — TUN ядра (D-97).
            if (failure.code == DiagCode.LOCAL_PROXY_UNAVAILABLE || failure.code == DiagCode.TUN_ESTABLISH_FAILED) {
                log.diagnostic(failure)
                records += AttemptRecord(p.id, reasons, false, failure)
                return ConnectionReport.Failed(failure, records, plan)
            }
            book.recordFailure(p.id, failure.code, clock.nowMillis())
            observe(p, startedAt, success = false, stalled = failure.code == DiagCode.PAYLOAD_STALLED)
            log.diagnostic(failure)
            records += AttemptRecord(p.id, reasons, false, failure)
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

    /**
     * [shareRefused] — раздача не поднялась, и попытка шла без неё (D-51).
     * [Fail.split] — ClientHello к серверу и правда разбивался (D-68): ядро
     * не ответило «разбивать нечего».
     */
    private sealed interface Try {
        val shareRefused: Diagnostic?

        data class Ok(val session: EngineSession, override val shareRefused: Diagnostic? = null) : Try
        data class Fail(val reason: Diagnostic, override val shareRefused: Diagnostic? = null, val split: Boolean = false) : Try
    }

    private suspend fun tryOne(
        ir: ConfigIr,
        p: ServerProfile,
        tun: TunInput?,
        share: ShareSpec?,
        split: Boolean,
        sites: SplitSites,
        local: LocalProxySpec? = null,
        systemTun: SystemTun? = null,
    ): Try {
        val c = compiler.compile(ir, CompilePlan(p.id, tun != null || systemTun != null, share, split, sites, local, systemTun))
        val compiled = when (c) {
            is Outcome.Failure -> return Try.Fail(c.errors.first())
            is Outcome.Success -> c.value
        }
        // Предупреждения сборки — в журнал (раньше успех их терял): например,
        // «разбивать нечего» у сервера без TLS (D-68).
        c.diagnostics.forEach(log::diagnostic)
        val applied = split && c.diagnostics.none { it.code == DiagCode.CLIENT_HELLO_SPLIT_NOT_APPLIED }
        (engine.validate(compiled) as? Outcome.Failure)?.let { return Try.Fail(it.errors.first()) }
        val session = when (val s = engine.start(compiled, tun)) {
            is Outcome.Failure -> {
                val reason = s.errors.first()
                // Локальный прокси (D-95) без раздачи: ядро проверено (validate), запуск
                // упал — значит, не встал вход на 127.0.0.1 (порт заняли после проверки).
                // Без входа подключение не нужно; сервер не виноват.
                if (share == null && local != null && reason.code == DiagCode.BACKEND_START_FAILED) {
                    return Try.Fail(
                        Diagnostic.error(
                            DiagCode.LOCAL_PROXY_UNAVAILABLE,
                            "локальный прокси на ${LocalProxySpec.ADDRESS}:${local.port} не поднялся — порт, скорее всего, занят; сменить — «Сменить порт и пароль»",
                        ).withCause(reason),
                    )
                }
                // TUN ядра (Windows, D-97): адаптер Wintun и фильтры WFP встают при
                // запуске ядра, конфигурация проверена — отказ этого ПК, а не сервера.
                if (share == null && systemTun != null && reason.code == DiagCode.BACKEND_START_FAILED) return Try.Fail(systemTunFailed(reason))
                // Вход раздачи не встал (адрес пропал, порт занят — D-51): это отказ
                // запуска, а не сервера. Та же попытка без раздачи; запустилась —
                // туннель работает без неё, и сервер не наказывается.
                if (share == null || reason.code != DiagCode.BACKEND_START_FAILED) return Try.Fail(reason)
                val refused = Diagnostic.warning(DiagCode.BACKEND_START_FAILED, "раздача не поднялась: ядро с её входами не запустилось — туннель без раздачи")
                    .withCause(reason)
                return when (val t = tryOne(ir, p, tun, null, split, sites, local, systemTun)) {
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
            return Try.Fail(result.errors.first(), split = applied)
        }
        // Успех с оговоркой (например, здоровье не проверено, D-32) — в журнал, а не мимо.
        result.diagnostics.forEach(log::diagnostic)
        return Try.Ok(session)
    }

    private companion object {
        /** Причины в записи попытки — видны в «Почему этот сервер» (D-69). */
        const val SPLIT_REJECTED = "сервер не принял разбитый ClientHello — без разбиения"
        const val SPLIT_REMEMBERED = "без разбиения ClientHello: этот сервер его не принял"
    }
}

/**
 * Ядро не запустилось с TUN, который создаёт само (Windows, D-97): адаптер
 * Wintun или фильтры WFP не встали. Это отказ TUN этого ПК — у следующих
 * кандидатов то же, и сервер не наказывается; окно предлагает подключение
 * без VPN (D-95, `LocalProxyOffer`).
 */
internal fun systemTunFailed(reason: Diagnostic): Diagnostic = Diagnostic.error(
    DiagCode.TUN_ESTABLISH_FAILED,
    "ядро не подняло адаптер Wintun или фильтры WFP (D-97) — отказ туннеля этого ПК, а не сервера; рядом с javaw.exe должен лежать wintun.dll",
).withCause(reason)
