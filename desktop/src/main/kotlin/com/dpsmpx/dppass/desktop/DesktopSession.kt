package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.toTunInput
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.tunnel.TunnelHandle
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext

/** Состояние туннеля для окна. */
sealed interface SessionStatus {
    data object Disconnected : SessionStatus

    data class Connecting(val server: String?) : SessionStatus

    data class Connected(val profileId: ProfileId, val server: String, val sinceMillis: Long) : SessionStatus

    data object Disconnecting : SessionStatus

    data class Failed(val reason: Diagnostic) : SessionStatus
}

/**
 * Сеанс туннеля на Linux (D-74) — путь `DPpassVpnService` без Android:
 * спецификация → TUN → план кандидатов с пробой здоровья (D-15, D-32) →
 * сеанс ядра; отключение — ядро, затем TUN и правила. Раздачи, устройства
 * раздачи, режима без сервера и наблюдателя сеанса в первой версии нет;
 * переподключение к новым серверам подписки — [reconnect] (D-77).
 */
class DesktopSession(private val graph: DesktopGraph, private val scope: CoroutineScope) {
    private val state = MutableStateFlow<SessionStatus>(SessionStatus.Disconnected)
    val status: StateFlow<SessionStatus> = state

    private val lock = Mutex()

    // Окно зовёт с потока EDT, автообновление (D-77) — из фона.
    @Volatile
    private var job: Job? = null

    @Volatile
    private var session: EngineSession? = null

    @Volatile
    private var tunnel: TunnelHandle? = null

    /** Трафик сеанса; null — ядро не запущено. */
    fun traffic(): TrafficStats? = session?.stats()

    fun connect(preferred: ProfileId?) {
        if (job?.isActive == true) return
        job = scope.launch { lock.withLock { connectNow(preferred) } }
    }

    /** Подключённый сервер; null — туннеля нет. */
    fun connectedProfile(): ProfileId? = (state.value as? SessionStatus.Connected)?.profileId

    /**
     * Переподключить к новым серверам подписки (D-77): сеанс — стоп, затем
     * план заново, начиная с [preferred]. Пока ждали блокировку, отключились —
     * переподключать нечего.
     */
    fun reconnect(preferred: ProfileId?) {
        val running = job
        job = scope.launch {
            running?.cancel()
            running?.join()
            lock.withLock {
                if (session == null) return@withLock
                stopNow()
                connectNow(preferred)
            }
        }
    }

    fun disconnect() {
        val running = job
        scope.launch {
            running?.cancel()
            running?.join()
            lock.withLock { stopNow() }
        }
    }

    /**
     * Выход процесса: без корутин и блокировок — поток `Runtime.addShutdownHook`.
     * Ядро останавливается мостом напрямую, затем TUN и правила.
     */
    fun shutdownNow() {
        if (session != null) graph.runtime?.stop()
        tunnel?.close()
        session = null
        tunnel = null
    }

    private suspend fun connectNow(preferred: ProfileId?) {
        if (session != null) return
        val core = graph.core
        state.value = SessionStatus.Connecting(null)
        val ir = core.activation.state.activeConfig
            ?: return fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — добавьте подписку или импортируйте серверы"))
        val spec = when (val s = core.tunnelSpecFor(ir)) {
            is Outcome.Failure -> return fail(s.errors.first())
            is Outcome.Success -> s.value
        }
        val handle = when (val t = withContext(Dispatchers.IO) { graph.tunnels.establish(spec) }) {
            is Outcome.Failure -> {
                t.errors.drop(1).forEach(core.log::diagnostic)
                return fail(t.errors.first())
            }
            is Outcome.Success -> t.value
        }
        // Проба здоровья (D-32) блокирует поток — не дольше своего срока, меньше срока плана.
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, profile ->
            state.value = SessionStatus.Connecting(profile.name)
            withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, probeTimeout) }
        }
        val report = try {
            core.connect(null, checker, handle.toTunInput(), preferred) { delay(it) }
        } catch (e: CancellationException) {
            // Сеанс, запущенный посреди проверки, оркестратор уже остановил; остаётся TUN.
            withContext(NonCancellable + Dispatchers.IO) { handle.close() }
            state.value = SessionStatus.Disconnected
            throw e
        }
        when (report) {
            is ConnectionReport.Connected -> {
                session = report.session
                tunnel = handle
                val name = ir.profiles.firstOrNull { it.id == report.profileId }?.name ?: report.profileId.value
                core.log.info("connected", "profile" to Safe(report.profileId.value), "attempts" to report.attempts.size)
                state.value = SessionStatus.Connected(report.profileId, name, core.clock.nowMillis())
            }
            is ConnectionReport.Failed -> {
                withContext(Dispatchers.IO) { handle.close() }
                fail(report.reason)
            }
            null -> {
                withContext(Dispatchers.IO) { handle.close() }
                fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — подключаться не к чему"))
            }
        }
    }

    private suspend fun stopNow() {
        val s = session ?: run {
            if (state.value !is SessionStatus.Failed) state.value = SessionStatus.Disconnected
            return
        }
        state.value = SessionStatus.Disconnecting
        withContext(NonCancellable) {
            s.stop()
            withContext(Dispatchers.IO) { tunnel?.close() }
        }
        session = null
        tunnel = null
        graph.core.log.info("disconnected")
        state.value = SessionStatus.Disconnected
    }

    private fun fail(reason: Diagnostic) {
        graph.core.log.diagnostic(reason)
        state.value = SessionStatus.Failed(reason)
    }

    private companion object {
        const val PROBE_MARGIN_MILLIS = 2_000L
    }
}
