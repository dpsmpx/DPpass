package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.Degradation
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
import java.util.Collections

/** Состояние туннеля для окна. */
sealed interface SessionStatus {
    data object Disconnected : SessionStatus

    data class Connecting(val server: String?) : SessionStatus

    data class Connected(val profileId: ProfileId, val server: String, val sinceMillis: Long) : SessionStatus

    data object Disconnecting : SessionStatus

    data class Failed(val reason: Diagnostic) : SessionStatus
}

/**
 * Сбой сервера сеанса (D-58, D-78): [asked] — вопрос, перейти ли с [from] на
 * [to]; иначе — сообщение, что DPpass перешёл сам (автопереключение).
 */
data class ServerNotice(val from: ServerProfile, val to: ServerProfile, val reason: Diagnostic, val asked: Boolean)

/**
 * Сеанс туннеля на Linux (D-74) — путь `DPpassVpnService` без Android:
 * спецификация → TUN → план кандидатов с пробой здоровья (D-15, D-32) →
 * сеанс ядра; отключение — ядро, затем TUN и правила. Переподключение к
 * новым серверам подписки — [reconnect] (D-77). Пока сеанс идёт, его
 * наблюдает [SessionWatch] (D-78): подтверждённый сбой — переподключение,
 * вопрос о замене выбранного сервера ([notice]) или замена с согласием
 * заранее. Раздачи, устройства раздачи и режима без сервера в первой
 * версии нет.
 */
class DesktopSession(private val graph: DesktopGraph, private val scope: CoroutineScope, private val prefs: DesktopPrefs) {
    private val state = MutableStateFlow<SessionStatus>(SessionStatus.Disconnected)
    val status: StateFlow<SessionStatus> = state

    private val noticeState = MutableStateFlow<ServerNotice?>(null)

    /** Вопрос о замене сервера или сообщение о ней (D-58); null — нечего показывать. */
    val notice: StateFlow<ServerNotice?> = noticeState

    /** Серверы, о которых пользователь ответил «Остаться» (D-58): до отключения. */
    private val declined: MutableSet<ProfileId> = Collections.synchronizedSet(HashSet())

    @Volatile
    private var watch: Job? = null

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

    /** «Перейти» (D-58): замена — только из действующей конфигурации, иначе — с прежним выбором. */
    fun acceptSwitch() {
        val n = noticeState.value?.takeIf { it.asked } ?: return
        noticeState.value = null
        val core = graph.core
        if (core.activation.state.activeConfig?.profiles?.any { it.id == n.to.id } == true) {
            prefs.selectedServer = n.to.id
            core.log.info("server_switched", "from" to Safe(n.from.id.value), "to" to Safe(n.to.id.value), "by" to Safe("user"))
        } else {
            core.log.info("server_switch_stale")
        }
        if (session != null) reconnect(prefs.selectedServer) else connect(prefs.selectedServer)
    }

    /** «Остаться» (D-58): о сбоях этого сервера не спрашивать до отключения. */
    fun keepServer() {
        val n = noticeState.value?.takeIf { it.asked } ?: return
        noticeState.value = null
        declined += n.from.id
        graph.core.log.info("server_switch_declined", "profile" to Safe(n.from.id.value))
    }

    /** Сообщение об автопереключении прочитано. */
    fun dismissNotice() {
        if (noticeState.value?.asked == false) noticeState.value = null
    }

    fun disconnect() {
        // Ответ «Остаться» и вопрос — до отключения (D-58).
        declined.clear()
        noticeState.value = null
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
        watch?.cancel()
        if (session != null) graph.runtime?.stop()
        tunnel?.close()
        session = null
        tunnel = null
        // Опыт адаптивной модели — на диск (D-44).
        graph.core.persistStability()
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
        // Белый список по свежей проверке в этой сети (D-64, D-79): порядок плана и опыт попыток — его.
        val regime = graph.networkCheck.regime()
        regime?.let { core.log.info("network_regime", "class" to it.restriction) }
        val failingUnderRegime = regime?.let(core::failingUnder).orEmpty()
        val report = try {
            core.connect(null, checker, handle.toTunInput(), preferred, regime = regime) { delay(it) }
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
                // Подключился сервер, который под белым списком только отказывал: список, скорее всего,
                // выключили — режим снова неизвестен (D-64).
                if (regime != null && report.profileId in failingUnderRegime) {
                    graph.networkCheck.forgetRegime()
                    core.log.info("network_regime_dropped", "reason" to Safe("contradicted"), "profile" to Safe(report.profileId.value))
                }
                state.value = SessionStatus.Connected(report.profileId, name, core.clock.nowMillis())
                val profile = ir.profiles.firstOrNull { it.id == report.profileId }
                val w = SessionWatch(
                    core,
                    report.profileId,
                    profile,
                    { graph.engine.probeHealth(ir.dns, probeTimeout) },
                    { prefs.selectedServer },
                    { prefs.autoSwitch },
                    { synchronized(declined) { declined.toSet() } },
                    regime.takeIf { report.profileId !in failingUnderRegime },
                    graph.networkCheck::probesQuiet,
                )
                watch = scope.launch { onDegraded(withContext(Dispatchers.IO) { w.run { delay(it) } }) }
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

    /** Сбой подтверждён (D-58): вопрос или замена — и переподключение по выбору, как он есть теперь. */
    private fun onDegraded(d: Degradation) {
        val log = graph.core.log
        when (d) {
            is Degradation.Reconnect -> Unit
            is Degradation.Ask -> {
                noticeState.value = ServerNotice(d.from, d.to, d.reason, asked = true)
                log.info("server_switch_offered", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value))
            }
            is Degradation.Switch -> {
                prefs.selectedServer = d.to.id
                noticeState.value = ServerNotice(d.from, d.to, d.reason, asked = false)
                log.info("server_switched", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value), "by" to Safe("auto"))
            }
        }
        // Пока на вопрос нет ответа — к прежнему выбору, как на Android.
        reconnect(prefs.selectedServer)
    }

    private suspend fun stopNow() {
        watch?.cancel()
        watch = null
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
        withContext(NonCancellable + Dispatchers.IO) { graph.core.persistStability() }
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
