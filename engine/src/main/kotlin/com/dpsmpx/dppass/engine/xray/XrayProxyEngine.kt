package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineCapabilities
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
            if (current != null) {
                return Outcome.failure(DiagCode.BACKEND_ALREADY_RUNNING, "ядро уже запущено; сначала stop()")
            }
            val r = rt.start(payload, tun?.fd ?: NO_TUN, tun?.mtu ?: 0, tun?.protector)
            if (r is XrayResult.Failed) return failed(r, "ядро Xray не запустилось")
            val session = Session(config, rt)
            current = session
            return Outcome.Success(session)
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
     * Выпускает ли сервер запущенной сессии IPv6 (D-66, [XrayIpv6]): не больше
     * трёх проб DNS по [XrayIpv6.TIMEOUT_MILLIS]. Блокирует поток.
     */
    fun probeIpv6(): Ipv6Check {
        val rt = when (runtime) {
            is Outcome.Failure -> return Ipv6Check(Ipv6Egress.UNKNOWN, emptyList())
            is Outcome.Success -> runtime.value
        }
        return XrayIpv6.probe { target -> rt.probeDns(target, XrayIpv6.TIMEOUT_MILLIS).outcome }
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
