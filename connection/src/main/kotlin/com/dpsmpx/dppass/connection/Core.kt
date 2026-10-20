package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ConfigWriter
import com.dpsmpx.dppass.config.LoadedConfig
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.core.RuleId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.DiagnosticReport
import com.dpsmpx.dppass.diagnostics.LogHistory
import com.dpsmpx.dppass.diagnostics.LogSink
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.diagnostics.map
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.routing.AppPolicy
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy
import com.dpsmpx.dppass.routing.Rule
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.storage.BlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.storage.StorageRecovery
import com.dpsmpx.dppass.subscriptions.FilterResult
import com.dpsmpx.dppass.subscriptions.ProfileFilter
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionCandidate
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.tunnel.PlatformTraits
import com.dpsmpx.dppass.tunnel.TunnelHandle
import com.dpsmpx.dppass.tunnel.TunnelSpec
import com.dpsmpx.dppass.tunnel.TunnelSpecBuilder
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.withContext

/**
 * Поднятый TUN → вход ядра: fd, MTU спецификации и защита сокетов ядра
 * от этого же TUN (D-25). `tunnel` и `engine` друг о друге не знают —
 * встречаются здесь.
 */
fun TunnelHandle.toTunInput(): TunInput = TunInput(fd, spec.mtu, SocketProtector(::protect))

/**
 * Фильтр серверов подписки по возможностям ядра: исключение — всегда с
 * предупреждением, путь — место записи в теле подписки (`entry[k]`).
 */
class EngineProfileFilter(private val caps: EngineCapabilities) : ProfileFilter {
    override fun filter(profiles: List<ServerProfile>, paths: List<String>): FilterResult {
        require(paths.size == profiles.size) { "путь — у каждого профиля" }
        val usable = mutableListOf<ServerProfile>()
        val notes = mutableListOf<Diagnostic>()
        for ((i, p) in profiles.withIndex()) {
            val problems = CapabilityChecker.checkProfile(p, caps, paths[i])
            if (problems.any { it.isError }) {
                notes += Diagnostic.warning(DiagCode.PROFILE_EXCLUDED_UNSUPPORTED, "сервер «${p.name}» исключён: ядро его не поддерживает", paths[i])
                    .copy(causes = problems)
            } else {
                usable += p
            }
        }
        return FilterResult(usable, notes)
    }
}

/**
 * Сборка ядра DPpass: один объект, через который `app/` (Android) и
 * `cli` (JVM) делают одно и то же. Платформенное — снаружи: ядро
 * прокси, хранилище, часы, приёмник журнала, черты платформы.
 *
 * Здесь нет ничего про Android и ничего про конкретное ядро.
 */
class DPpassCore(
    val compiler: BackendCompiler,
    val engine: ProxyEngine,
    store: BlobStore,
    val clock: Clock,
    private val selfPackage: String,
    private val platform: PlatformTraits,
    val logSink: LogSink = MemoryLogSink(),
    val policy: ConnectionPolicy = ConnectionPolicy(),
    /** Сброс хранилища, которое не читается (на Android — `StorageReset`); null — оболочка его не даёт. */
    private val storageRecovery: StorageRecovery? = null,
    /**
     * Что ещё оболочка знает о ядре — строки раздела «Engine» отчёта: на
     * Android — из чего собран набор геоданных (D-27).
     */
    private val engineDetails: List<Pair<String, String>> = emptyList(),
) {
    val log: Logger = Logger("core", logSink, clock::nowMillis)
    private val quarantine = Quarantine(store, clock)
    val activation: ActivationService = ActivationService(compiler, engine, ActivationStore(store, quarantine), clock)
    val health: HealthBook = HealthBook(policy)

    /** Задержка до серверов по последнему замеру (D-41). */
    val latency: LatencyBook = LatencyBook()

    /** Серверы, не принявшие разбитый ClientHello (D-69): до перезапуска процесса. */
    val splitMemory: SplitMemory = SplitMemory()

    /** Хранение адаптивной модели (D-44). */
    private val stabilityStore = StabilityBook(store, quarantine)

    /** Адаптивная модель устойчивости (D-44): читается из хранилища один раз. */
    val stability: StabilityModel = stabilityStore.load().also { it.diagnostics.forEach(log::diagnostic) }.valueOrNull() ?: StabilityModel()
    private val loader = ConfigLoader()

    /** Сохранённые подписки: загрузка, идентификатор устройства, применение (D-33, D-36, D-39, D-42). */
    val subscriptions: SubscriptionService = SubscriptionService(SubscriptionBook(store, quarantine), this, clock)

    /** Политика пользователя: маршрутизация, DNS, приложения (D-38). */
    val userPolicy: PolicyService = PolicyService(PolicyStore(store, quarantine), this)

    /** Раздача туннеля другим устройствам (D-51): включена ли, порт, логин и пароль. */
    val share: ShareService = ShareService(ShareStore(store, quarantine))

    /** Доверенные устройства раздачи — подключение через другой DPpass (D-55). */
    val relays: RelayService = RelayService(RelayStore(store, quarantine), clock)

    fun restore(): List<Diagnostic> = activation.restore().also { it.forEach(log::diagnostic) }

    /**
     * Сброс хранилища — только действием пользователя (D-19), когда
     * сохранённое не прочитать: прежде всего `STORAGE_DATA_KEY_LOST`. Всё
     * сохранённое откладывается как есть, ключ данных создаётся заново,
     * состояние начинается с пустого; исходники — у пользователя.
     * Результат — куда отложено.
     */
    fun resetStorage(): Outcome<String> {
        val recovery = storageRecovery ?: return Outcome.failure(DiagCode.INTERNAL_ERROR, "сброс хранилища в этой оболочке не подключён")
        return when (val r = recovery.reset()) {
            is Outcome.Failure -> r.also { it.diagnostics.forEach(log::diagnostic) }
            is Outcome.Success -> {
                log.info("storage.reset", "moved_to" to r.value)
                Outcome.Success(r.value, restore())
            }
        }
    }

    /**
     * Активная конфигурация документом текущего формата (D-11); null —
     * активной нет. По умолчанию секреты заменены меткой: такой документ
     * можно показать, но не активировать. [ConfigWriter.Mode.FULL] — только
     * явным действием пользователя («экспорт с секретами»).
     */
    fun export(mode: ConfigWriter.Mode = ConfigWriter.Mode.REDACTED): String? = activation.state.activeConfig?.let { ConfigWriter.write(it, mode) }

    /**
     * Разбор документа. Отвергнутый импорт не сохраняется: исходник —
     * у пользователя (он его и передал); карантин — только для того,
     * что DPpass сам хранил и не смог прочитать.
     */
    fun load(text: String): Outcome<LoadedConfig> = loader.load(text).also { r ->
        r.diagnostics.filter { it.isError }.forEach(log::diagnostic)
    }

    /** Документ пользователя → активная конфигурация (или отказ с сохранённой прежней). */
    suspend fun importAndActivate(text: String, preCheck: PreActivationCheck? = null): Outcome<ActivationResult> {
        val loaded = when (val l = load(text)) {
            is Outcome.Failure -> return l
            is Outcome.Success -> l.value
        }
        val r = activation.activate(loaded.ir, PolicyService.OWN_DOCUMENT, loaded.sourceChecksum, preCheck = preCheck)
        logActivation(r)
        return Outcome.Success(r)
    }

    /**
     * Кандидат подписки → активация. Маршрутизация и DNS — пользователя
     * (базовая конфигурация), если подписка не привязана к маршрутизации
     * поставщика явно. Подписка получает новую удачную ревизию только
     * после успешной активации.
     */
    suspend fun activateSubscription(base: ConfigIr, candidate: SubscriptionCandidate): Pair<Subscription, ActivationResult> {
        val ir = base.copy(
            profiles = candidate.profiles,
            routing = candidate.providerRouting ?: base.routing,
            dns = candidate.providerDns ?: base.dns,
        )
        val r = activation.activate(ir, "subscription:${candidate.subscription.id}#${candidate.revision.number}", candidate.revision.checksum)
        logActivation(r)
        val sub = when (r) {
            is ActivationResult.Activated -> candidate.subscription.recordSuccess(candidate.revision, candidate.metadata)
            is ActivationResult.Rejected -> candidate.subscription.recordFailure(
                com.dpsmpx.dppass.subscriptions.FailedRevision(candidate.revision.checksum, clock.nowMillis(), r.diagnostics.first()),
            )
        }
        return sub to r
    }

    fun profileFilter(): ProfileFilter = EngineProfileFilter(compiler.capabilities)

    /**
     * План подключения; [preferred] — сервер, выбранный пользователем: первым
     * в плане (D-34). [regime] — режим сети по свежей проверке (D-64): только
     * порядок, без исключений.
     */
    fun plan(assessment: NetworkAssessment?, preferred: ProfileId? = null, regime: NetworkAssessment? = null): ConnectionPlan? {
        val ir = activation.state.activeConfig ?: return null
        return CandidatePlanner.plan(
            ir, compiler.capabilities, assessment, health, health.lastGood(), clock.nowMillis(), policy, preferred, latency::millis, stability, regime,
        )
    }

    /**
     * Серверы, которые под режимом [regime] чаще отказывали, чем работали
     * (D-64). Подключение к одному из них опровергает режим: белый список,
     * скорее всего, выключили.
     */
    fun failingUnder(regime: NetworkAssessment): Set<ProfileId> = stability.failingIn(NetworkContext.of(regime))

    suspend fun connect(
        assessment: NetworkAssessment?,
        checker: HealthChecker,
        tun: TunInput?,
        preferred: ProfileId? = null,
        /** Раздача туннеля другим устройствам (D-51); null — без раздачи. */
        share: ShareSpec? = null,
        /** Режим сети по свежей проверке (D-64): порядок плана и контекст опыта попыток. */
        regime: NetworkAssessment? = null,
        /** Разбивать ClientHello к серверу (D-68): выбор пользователя, по умолчанию — нет. */
        splitClientHello: Boolean = false,
        /** Сайты напрямую с разбиением (D-72): список пользователя, по умолчанию пуст. */
        splitSites: SplitSites = SplitSites.NONE,
        pause: suspend (Long) -> Unit,
    ): ConnectionReport? {
        val ir = activation.state.activeConfig ?: return null
        val plan = plan(assessment, preferred, regime) ?: return null
        val orchestrator = ConnectionOrchestrator(compiler, engine, checker, health, clock, log, policy, stability, assessment ?: regime, splitMemory, pause)
        return orchestrator.connect(ir, plan, tun, share, splitClientHello, splitSites)
    }

    /** Наблюдатель сессии (D-44): Android-слой кормит его пробами (D-32). */
    fun supervisor(profileId: ProfileId, assessment: NetworkAssessment?): SessionSupervisor =
        SessionSupervisor(stability, profileId, NetworkContext.of(assessment))

    /**
     * Подтверждённая деградация сессии на [profileId] (D-44, D-58). Отказ —
     * в журнал здоровья: сервер перестаёт быть «последним удачным» и уходит
     * на паузу, и план без выбора пользователя начнёт с другого кандидата.
     *
     * Выбранный пользователем сервер ([preferred], D-34) молча не
     * заменяется (D-05): замена — первый кандидат плана без выбора, а
     * переход — с согласия пользователя; [autoSwitch] — согласие заранее.
     * [declined] — серверы, о которых пользователь ответил «Остаться».
     */
    fun degraded(
        profileId: ProfileId,
        reason: Diagnostic,
        preferred: ProfileId?,
        autoSwitch: Boolean,
        declined: Set<ProfileId> = emptySet(),
        /** Режим сети (D-64): замена — первая в плане по тому же режиму. */
        regime: NetworkAssessment? = null,
    ): Degradation {
        health.recordFailure(profileId, reason.code, clock.nowMillis())
        // Устройство раздачи (D-55) в активной конфигурации не значится — его не заменяют.
        val from = activation.state.activeConfig?.profiles?.firstOrNull { it.id == profileId }
        if (from == null || profileId != preferred || profileId in declined) return Degradation.Reconnect(reason)
        val to = plan(null, regime = regime)?.attempts?.firstOrNull { it.profile.id != profileId }?.profile ?: return Degradation.Reconnect(reason)
        return if (autoSwitch) Degradation.Switch(from, to, reason) else Degradation.Ask(from, to, reason)
    }

    /** Сохранить адаптивную модель (D-44): вызывает сервис при остановке и периодически. */
    fun persistStability(): Outcome<Unit> = stabilityStore.save(stability)

    fun tunnelSpec(): Outcome<TunnelSpec>? = activation.state.activeConfig?.let(::tunnelSpecFor)

    fun tunnelSpecFor(ir: ConfigIr): Outcome<TunnelSpec> = TunnelSpecBuilder.build(ir, selfPackage, platform)

    /**
     * Конфигурация подключения через устройство раздачи (D-55): единственный
     * сервер — само устройство по найденному адресу [at]; маршрутизация и DNS
     * — те же, что у подписки (свой документ, если он действует, иначе
     * политика пользователя). Активация не меняется: устройство живёт в своём
     * списке, а подписки и свой документ — в своих.
     */
    fun relayConfig(device: RelayDevice, at: IpAddress): ConfigIr = userPolicy.baseFor(activation.state).copy(profiles = listOf(device.profile(at)))

    /**
     * Подключение через устройство раздачи (D-55): план из одного кандидата —
     * его выбрал пользователь, поэтому пауза после прошлого отказа его не
     * откладывает. Отказ устройства — отказ подключения: другие серверы
     * молча не подставляются (D-05) — пользователь просил именно это
     * устройство.
     */
    suspend fun connectVia(
        device: RelayDevice,
        at: IpAddress,
        checker: HealthChecker,
        tun: TunInput?,
        share: ShareSpec? = null,
        pause: suspend (Long) -> Unit,
    ): ConnectionReport {
        val ir = relayConfig(device, at)
        val plan = CandidatePlanner.plan(
            ir, compiler.capabilities, null, health, health.lastGood(), clock.nowMillis(), policy, device.profileId, latency::millis, stability,
        )
        log.info("relay_connect", "device" to Safe(device.id), "port" to device.port)
        val orchestrator = ConnectionOrchestrator(compiler, engine, checker, health, clock, log, policy, stability, null, pause = pause)
        val report = orchestrator.connect(ir, plan, tun, share)
        // Вход раздачи ответил, а данные не пошли (D-59): сбоит туннель того телефона, а не сервер.
        val failure = (report as? ConnectionReport.Failed)?.attempts?.singleOrNull()?.failure
        if (report !is ConnectionReport.Failed || failure == null || failure.code !in RELAY_HEALTH_CODES) return report
        val d = Diagnostic.error(
            DiagCode.RELAY_UPSTREAM_FAILED,
            "устройство раздачи приняло логин и пароль, но данные через него не идут: у DPpass на раздающем телефоне нет связи со своим сервером — проверьте подключение там",
        ).withCause(failure)
        log.diagnostic(d)
        return report.copy(reason = d)
    }

    /**
     * Почему соединение пошло бы так (D-09): решение по активной
     * конфигурации на геоданных ядра (D-27). null — активной конфигурации
     * нет; отказ — геоданные ядра не ответили. Блокирует поток: первое
     * обращение к коду geosite или geoip читает файл набора.
     */
    fun explain(query: RouteQuery): Outcome<RouteDecision>? = activation.state.activeConfig?.let { engine.explain(it.routing, query) }

    /** Список «Напрямую с разбиением» (D-72) против ядра: коды geosite — по набору геоданных (D-27). */
    fun checkSplitSites(sites: SplitSites): List<Diagnostic> = compiler.checkSplitSites(sites)

    /**
     * Попадает ли соединение в список «Напрямую с разбиением» (D-72): тот же
     * смысл, что у правила ядра — домен с поддоменами или список geosite на
     * наборе геоданных ядра (D-27). Для «Проверить маршрут»: список сильнее
     * документа и проверяется раньше него.
     */
    fun matchesSplitSites(query: RouteQuery, sites: SplitSites, apps: AppPolicy? = activation.state.activeConfig?.routing?.apps): Outcome<Boolean> {
        if (sites.isEmpty || query.domain == null) return Outcome.Success(false)
        // Приложение вне туннеля до ядра не доходит — списку там нечего решать.
        val pkg = query.packageName
        if (pkg != null && apps != null && !apps.includes(pkg)) return Outcome.Success(false)
        val probe = RoutingPolicy(rules = listOf(Rule(SPLIT_SITES_RULE, sites.conditions(), RouteAction.DIRECT)), defaultAction = RouteAction.PROXY)
        return engine.explain(probe, query.copy(packageName = null)).map { it.ruleId == SPLIT_SITES_RULE }
    }

    /**
     * Без сервера (D-73): серверов нет (ни подписки, ни своего документа),
     * устройство раздачи не выбрано, и туннелю есть что делать. Есть
     * серверы — подключение только через них: их отказ на этот режим не
     * переключает (D-05).
     */
    fun serverlessReady(sites: SplitSites, settings: ServerlessSettings, relaySelected: Boolean): Boolean =
        activation.state.activeConfig == null && !relaySelected && ServerlessMode.useful(sites, settings)

    /** Конфигурация режима без сервера — для TUN и «Проверить маршрут». */
    fun serverlessConfig(settings: ServerlessSettings): ConfigIr = ServerlessMode.config(settings, userPolicy.currentOrDefault())

    /**
     * Подключение без сервера (D-73): компиляция, проверка ядром, запуск и
     * [check] — проба DNS напрямую (с системным резолвером пробовать
     * нечего). Отказ пробы останавливает ядро: туннель, в котором имена не
     * резолвятся, хуже, чем его отсутствие. Отмена посреди пробы — тоже.
     */
    suspend fun connectServerless(
        tun: TunInput?,
        sites: SplitSites,
        settings: ServerlessSettings,
        check: suspend (EngineSession, DnsPolicy) -> Outcome<Unit>,
    ): Outcome<EngineSession> {
        val plan = ServerlessMode.plan(settings, sites, userPolicy.currentOrDefault())
        log.info(
            "serverless",
            "rest" to Safe(settings.rest.wire),
            "dns" to Safe(settings.dns.wire),
            "apps" to Safe(settings.apps.wire),
            "n" to sites.size,
        )
        val compiled = when (val c = compiler.compileServerless(plan.copy(withTun = tun != null))) {
            is Outcome.Failure -> return c
            is Outcome.Success -> c.also { it.diagnostics.forEach(log::diagnostic) }.value
        }
        (engine.validate(compiled) as? Outcome.Failure)?.let { return it }
        val session = when (val s = engine.start(compiled, tun)) {
            is Outcome.Failure -> return s
            is Outcome.Success -> s.value
        }
        val checked = try {
            check(session, plan.dns)
        } catch (e: CancellationException) {
            withContext(NonCancellable) { session.stop() }
            throw e
        }
        val failure = (checked as? Outcome.Failure)?.errors?.first() ?: return Outcome.Success(session)
        session.stop()
        return Outcome.failure(
            Diagnostic.error(
                failure.code,
                "без сервера DoH напрямую не ответил — имена не резолвятся; можно выбрать системный DNS: «Настройки» → «Без сервера» → «DNS»",
            ).withCause(failure),
        )
    }

    fun subscriptionNotes(result: UpdateResult): List<Diagnostic> = result.diagnostics.also { it.forEach(log::diagnostic) }

    /** Локальный отчёт (D-12): собирается на устройстве, наружу не отправляется. */
    fun report(extra: List<Diagnostic> = emptyList()): DiagnosticReport {
        val s = activation.state
        val logEvents = (logSink as? LogHistory)?.snapshot().orEmpty()
        return DiagnosticReport.Builder("DPpass diagnostic report")
            .section(
                "Engine",
                "backend" to compiler.capabilities.backendId,
                "version" to compiler.capabilities.backendVersion,
                *engineDetails.toTypedArray(),
            )
            .section(
                "Activation",
                "active_revision" to (s.active?.revision?.toString() ?: "none"),
                "active_profile" to (s.active?.profileId ?: "none"),
                "previous_revision" to (s.previous?.revision?.toString() ?: "none"),
                "history" to s.history.joinToString { "${it.revision}:${it.status}${it.failedStep?.let { st -> "@$st" } ?: ""}" },
            )
            .diagnostics(extra)
            .log(logEvents)
            .build()
    }

    private companion object {
        /** Отказы проверки здоровья (D-32): данные не пришли, «замерзли», проба не уложилась в срок. */
        val RELAY_HEALTH_CODES = setOf(DiagCode.ENDPOINT_UNREACHABLE, DiagCode.PAYLOAD_STALLED, DiagCode.HEALTH_CHECK_FAILED, DiagCode.TLS_HANDSHAKE_FAILED)

        /** Правило-проба списка «Напрямую с разбиением» (D-72): живёт только внутри [matchesSplitSites]. */
        val SPLIT_SITES_RULE = RuleId("split-sites")
    }

    internal fun logActivation(r: ActivationResult) {
        when (r) {
            is ActivationResult.Activated -> log.info("activated", "revision" to r.record.revision, "source" to Safe(r.record.source.substringBefore('#')))
            is ActivationResult.Rejected -> {
                log.warning("rejected", "revision" to r.record.revision, "step" to r.record.failedStep)
                r.diagnostics.filter { it.isError }.forEach(log::diagnostic)
            }
        }
    }
}
