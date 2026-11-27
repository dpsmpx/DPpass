package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.DesyncCounters
import com.dpsmpx.dppass.engine.Zapret2Stages
import com.dpsmpx.dppass.engine.EngineCapabilities
import com.dpsmpx.dppass.engine.EngineConnections
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.EngineState
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.routing.DnsPolicy
import com.dpsmpx.dppass.routing.RouteDecision
import com.dpsmpx.dppass.routing.RouteEvaluator
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.routing.RoutingPolicy

/**
 * [ProxyEngine] поверх моста Xray (D-25). Как и мост, держит одну сессию:
 * второй запуск без остановки — `BACKEND_ALREADY_RUNNING`, а не подмена.
 *
 * [runtime] — `Outcome`: библиотека ядра могла не загрузиться (нет
 * `.so`, другая версия), и тогда каждый вызов честно отвечает
 * `BACKEND_NOT_AVAILABLE` с исходной причиной, а не падает.
 *
 * Вызовы моста блокирующие и короткие (сборка конфигурации, запуск
 * ядра); поток выбирает вызывающий.
 */
class XrayProxyEngine(private val runtime: Outcome<XrayRuntime>) : ProxyEngine {
    override val capabilities: EngineCapabilities = XrayBackend.CAPABILITIES

    private val lock = Any()
    private var current: Session? = null
    private var hotspot: HotspotLease? = null

    override suspend fun validate(config: CompiledConfig): Outcome<Unit> {
        foreign<Unit>(config)?.let { return it }
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        return when (val r = rt.validate(config.payloadForEngine().encodeToByteArray())) {
            XrayResult.Ok -> Outcome.Success(Unit)
            XrayResult.Partial -> Outcome.Success(
                Unit,
                listOf(
                    Diagnostic.info(
                        DiagCode.BACKEND_VALIDATION_PARTIAL,
                        "ядро запущено: проверены сборка конфигурации и политика входов, полная проверка — при запуске (D-25)",
                    ),
                ),
            )
            is XrayResult.Failed -> failed(r, "ядро Xray отвергло конфигурацию")
        }
    }

    override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> {
        foreign<EngineSession>(config)?.let { return it }
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        val payload = config.payloadForEngine().encodeToByteArray()
        synchronized(lock) {
            if (current != null || hotspot != null) {
                return Outcome.failure(DiagCode.BACKEND_ALREADY_RUNNING, "ядро уже запущено; сначала stop()")
            }
            val r = rt.start(payload, tun?.fd ?: NO_TUN, tun?.mtu ?: 0, tun?.protector)
            if (r is XrayResult.Failed) return failed(r, "ядро Xray не запустилось")
            val session = Session(config, rt)
            current = session
            return Outcome.Success(session)
        }
    }

    /** Reserve the shared app engine before acquiring a private hotspot TUN.
     * The same AppGraph engine instance must be used by both callers.
     * No JNI calls, config changes, or automatic takeover here. */
    fun reserveHotspot(): HotspotLease? = synchronized(lock) {
        if (current != null || hotspot != null || runtime !is Outcome.Success) null
        else HotspotLease(runtime.value).also { hotspot = it }
    }

    enum class HotspotState { RESERVED, RUNNING, STOPPED, QUARANTINED, RELEASED }

    /**
     * One-shot exclusive lease. A failed native start other than RUNNING
     * may have touched the TUN; a failed native stop is not proof of closure.
     * No retry of a possibly foreign native stop, and no force release.
     * Only the trusted app owner may confirm descriptor retirement.
     */
    inner class HotspotLease internal constructor(private val rt: XrayRuntime) {
        private var phase = HotspotState.RESERVED
        private var attempted = false

        fun state(): HotspotState = synchronized(lock) { phase }

        fun start(config: CompiledConfig, tun: TunInput): Boolean = synchronized(lock) {
            check(hotspot === this && phase == HotspotState.RESERVED && !attempted)
            require(tun.fd >= 0 && tun.mtu in 576..1500)
            if (foreign<Unit>(config) != null) return@synchronized false
            attempted = true
            // Native start can have effects before throwing. Conservatively
            // retain ownership on every ambiguous response.
            phase = HotspotState.QUARANTINED
            val payload = config.payloadForEngine().encodeToByteArray()
            val result = try {
                rt.start(payload, tun.fd, tun.mtu, tun.protector)
            } finally {
                payload.fill(0)
            }
            when {
                result == XrayResult.Ok -> {
                    phase = HotspotState.RUNNING
                    true
                }
                result is XrayResult.Failed && result.kind == XrayFailureKind.RUNNING -> {
                    // Native bridge explicitly rejected a competing owner.
                    // Do not call its global stop or use its stats.
                    phase = HotspotState.STOPPED
                    false
                }
                else -> false
            }
        }

        /** Only a positively started exact lease is allowed to stop. */
        fun stop(): Boolean = synchronized(lock) {
            if (hotspot !== this) return@synchronized false
            when (phase) {
                HotspotState.RESERVED -> {
                    phase = HotspotState.STOPPED
                    true
                }
                HotspotState.STOPPED -> true
                HotspotState.RUNNING -> {
                    phase = HotspotState.QUARANTINED
                    if (rt.stop() != XrayResult.Ok || rt.traffic() != null) false
                    else {
                        phase = HotspotState.STOPPED
                        true
                    }
                }
                HotspotState.QUARANTINED, HotspotState.RELEASED -> false
            }
        }

        /** The caller must close its exact TUN and independently verify
         * retirement first. This cannot clear a quarantined native start
         * or stop, and a stale handle cannot release a new owner. */
        fun releaseAfterTunClosed(verifiedClosed: Boolean): Boolean = synchronized(lock) {
            if (hotspot !== this || phase != HotspotState.STOPPED || !verifiedClosed) {
                return@synchronized false
            }
            phase = HotspotState.RELEASED
            hotspot = null
            true
        }
    }

    /**
     * Проверка здоровья запущенной сессии (D-15, D-32): запрос DNS через
     * сервер профиля к DNS-серверу [dns], идущему через туннель
     * ([XrayHealth]). Блокирует поток не дольше [timeoutMillis].
     */
    fun probeHealth(dns: DnsPolicy, timeoutMillis: Int): Outcome<Unit> {
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        val (server, target) = XrayHealth.target(dns) ?: return XrayHealth.skipped()
        return XrayHealth.outcome(server, rt.probeDns(target, timeoutMillis))
    }

    /**
     * Без сервера (D-73): отвечает ли сервер DNS напрямую — запрос через
     * `proxy` (прямой выход с разбиением). Системный резолвер не пробуется:
     * успех без пробы. Блокирует поток не дольше [timeoutMillis].
     */
    fun probeServerless(dns: DnsPolicy, timeoutMillis: Int): Outcome<Unit> {
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        val (server, target) = XrayHealth.serverlessTarget(dns) ?: return Outcome.Success(Unit)
        return XrayHealth.outcome(server, rt.probeDns(target, timeoutMillis), via = XrayHealth.VIA_DIRECT)
    }

    /**
     * Выпускает ли сервер запущенной сессии IPv6 (D-66, [XrayIpv6]): не больше
     * трёх проб DNS по [XrayIpv6.TIMEOUT_MILLIS]. Блокирует поток.
     */
    fun probeIpv6(): Ipv6Check {
        val rt = when (runtime) {
            is Outcome.Failure -> return Ipv6Check(Ipv6Egress.UNKNOWN, emptyList())
            is Outcome.Success -> runtime.value
        }
        return XrayIpv6.probe { target -> rt.probeDns(target, XrayIpv6.TIMEOUT_MILLIS) }
    }

    /**
     * Замер через туннель запущенной сессии (D-61): пинг, jitter и скорость
     * загрузки через сервер профиля ([XraySpeed]). Блокирует поток до
     * [XraySpeed.TIMEOUT_MILLIS].
     */
    fun speedTest(): Outcome<SpeedReport> {
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        return XraySpeed.report(rt.speedTest(XraySpeed.TARGET, XraySpeed.PINGS, XraySpeed.MAX_BYTES, XraySpeed.MAX_TIME_MILLIS, XraySpeed.TIMEOUT_MILLIS))
    }

    /**
     * Объяснение решения (D-09) на наборе геоданных ядра ([XrayGeoResolver],
     * D-27). Ядро не запускается и не трогается; запущенному не мешает.
     */
    override fun explain(policy: RoutingPolicy, query: RouteQuery): Outcome<RouteDecision> {
        val rt = when (runtime) {
            is Outcome.Failure -> return unavailable()
            is Outcome.Success -> runtime.value
        }
        val geo = XrayGeoResolver(rt)
        val decision = RouteEvaluator(policy, geo).decide(query)
        return geo.failure?.let { Outcome.failure(it) } ?: Outcome.Success(decision)
    }

    /** Отказ моста → диагностика с кодом по виду отказа и текстом ядра в причине. */
    private fun <T> failed(r: XrayResult.Failed, message: String): Outcome<T> {
        val code = when (r.kind) {
            XrayFailureKind.CONFIG -> DiagCode.BACKEND_REJECTED_CONFIG
            XrayFailureKind.RUNNING -> DiagCode.BACKEND_ALREADY_RUNNING
            XrayFailureKind.START, XrayFailureKind.CONTRACT -> DiagCode.BACKEND_START_FAILED
        }
        return Outcome.failure(Diagnostic.error(code, message).withCause(r.cause(code)))
    }

    private fun <T> unavailable(): Outcome<T> {
        val reasons = (runtime as Outcome.Failure).errors
        return Outcome.failure(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, "ядро Xray недоступно").copy(causes = reasons))
    }

    private fun <T> foreign(config: CompiledConfig): Outcome<T>? = when {
        config.backendId != capabilities.backendId ->
            Outcome.failure(DiagCode.BACKEND_REJECTED_CONFIG, "конфигурация для ${config.backendId}, а ядро — ${capabilities.backendId}")
        config.backendVersion != capabilities.backendVersion ->
            Outcome.failure(DiagCode.BACKEND_REJECTED_CONFIG, "конфигурация для Xray ${config.backendVersion}, а ядро — ${capabilities.backendVersion} (D-18)")
        else -> null
    }

    /** Учёт соединений моста (D-106); библиотека не загружена — нечего включать. */
    override fun setConnectionTracking(on: Boolean) {
        (runtime as? Outcome.Success)?.value?.setConnectionTracking(on)
    }

    override fun connections(): EngineConnections? = (runtime as? Outcome.Success)?.value?.connections()

    override fun desyncCounters(): DesyncCounters? = (runtime as? Outcome.Success)?.value?.desyncStats()

    override fun zapret2Stages(): Zapret2Stages? = (runtime as? Outcome.Success)?.value?.zapret2Stages()

    private inner class Session(override val compiled: CompiledConfig, private val rt: XrayRuntime) : EngineSession {
        @Volatile
        private var state = EngineState.RUNNING

        @Volatile
        private var last = TrafficStats(0, 0)

        override fun state(): EngineState = state

        override fun stats(): TrafficStats {
            if (state == EngineState.RUNNING) rt.traffic()?.let { last = it }
            return last
        }

        override suspend fun stop() {
            synchronized(lock) {
                // Остановленная сессия не трогает ядро: оно может быть уже чужим.
                if (state != EngineState.RUNNING) return
                state = EngineState.STOPPING
                rt.traffic()?.let { last = it }
                state = if (rt.stop() is XrayResult.Failed) EngineState.FAILED else EngineState.STOPPED
                current = null
            }
        }
    }

    private companion object {
        const val NO_TUN = -1
    }
}
