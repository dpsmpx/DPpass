package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.LoadedConfig
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.DiagnosticReport
import com.dpsmpx.dppass.diagnostics.LogHistory
import com.dpsmpx.dppass.diagnostics.LogSink
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.BackendCompiler
import com.dpsmpx.dppass.engine.CapabilityChecker
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
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

/**
 * Поднятый TUN → вход ядра: fd, MTU спецификации и защита сокетов ядра
 * от этого же TUN (D-25). `tunnel` и `engine` друг о друге не знают —
 * встречаются здесь.
 */
fun TunnelHandle.toTunInput(): TunInput = TunInput(fd, spec.mtu, SocketProtector(::protect))

/** Фильтр серверов подписки по возможностям ядра: исключение — всегда с предупреждением. */
class EngineProfileFilter(private val caps: EngineCapabilities) : ProfileFilter {
    override fun filter(profiles: List<ServerProfile>): FilterResult {
        val usable = mutableListOf<ServerProfile>()
        val notes = mutableListOf<Diagnostic>()
        for ((i, p) in profiles.withIndex()) {
            val problems = CapabilityChecker.checkProfile(p, caps, "entry[$i]")
            if (problems.any { it.isError }) {
                notes += Diagnostic.warning(DiagCode.PROFILE_EXCLUDED_UNSUPPORTED, "сервер «${p.name}» исключён: ядро его не поддерживает", "entry[$i]")
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
    private val loader = ConfigLoader()

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
        val r = activation.activate(loaded.ir, "user-import", loaded.sourceChecksum, preCheck = preCheck)
        logResult(r)
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
        logResult(r)
        val sub = when (r) {
            is ActivationResult.Activated -> candidate.subscription.recordSuccess(candidate.revision, candidate.metadata)
            is ActivationResult.Rejected -> candidate.subscription.recordFailure(
                com.dpsmpx.dppass.subscriptions.FailedRevision(candidate.revision.checksum, clock.nowMillis(), r.diagnostics.first()),
            )
        }
        return sub to r
    }

    fun profileFilter(): ProfileFilter = EngineProfileFilter(compiler.capabilities)

    fun plan(assessment: NetworkAssessment?): ConnectionPlan? {
        val ir = activation.state.activeConfig ?: return null
        return CandidatePlanner.plan(ir, compiler.capabilities, assessment, health, health.lastGood(), clock.nowMillis(), policy)
    }

    suspend fun connect(assessment: NetworkAssessment?, checker: HealthChecker, tun: TunInput?, pause: suspend (Long) -> Unit): ConnectionReport? {
        val ir = activation.state.activeConfig ?: return null
        val plan = plan(assessment) ?: return null
        val orchestrator = ConnectionOrchestrator(compiler, engine, checker, health, clock, log, policy, pause)
        return orchestrator.connect(ir, plan, tun)
    }

    fun tunnelSpec(): Outcome<TunnelSpec>? = activation.state.activeConfig?.let { TunnelSpecBuilder.build(it, selfPackage, platform) }

    fun explain(query: RouteQuery): RouteDecision? = activation.state.activeConfig?.let { RouteEvaluator(it.routing).decide(query) }

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

    private fun logResult(r: ActivationResult) {
        when (r) {
            is ActivationResult.Activated -> log.info("activated", "revision" to r.record.revision, "source" to Safe(r.record.source.substringBefore('#')))
            is ActivationResult.Rejected -> {
                log.warning("rejected", "revision" to r.record.revision, "step" to r.record.failedStep)
                r.diagnostics.filter { it.isError }.forEach(log::diagnostic)
            }
        }
    }
}
