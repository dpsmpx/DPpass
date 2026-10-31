package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.connection.UsageAlert
import com.dpsmpx.dppass.connection.UsageMeter
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.desktop.ui.UsageText
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.LocalProxySpec
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.TrafficStats
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.routing.SplitSites
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
 * Раздача сеанса для окна (D-84): на каких адресах точки доступа открыт вход;
 * [refused] — ядро не открыло вход, и туннель работает без раздачи;
 * [source] — ответил ли NetworkManager, когда точки доступа не нашлось.
 */
data class ShareStatus(val endpoints: List<ShareSpec.Endpoint>, val refused: Boolean, val source: LinuxShareInterfaces.Source)

/**
 * Сеанс туннеля на ПК (D-74, D-97) — путь `DPpassVpnService` без Android:
 * спецификация → TUN (Linux) или описание адаптера для ядра (Windows) →
 * план кандидатов с пробой здоровья (D-15, D-32) →
 * сеанс ядра; отключение — ядро, затем TUN и правила. Переподключение к
 * новым серверам подписки — [reconnect] (D-77). Пока сеанс идёт, его
 * наблюдает [SessionWatch] (D-78): подтверждённый сбой — переподключение,
 * вопрос о замене выбранного сервера ([notice]) или замена с согласием
 * заранее; сменилась сеть — режим сессии заново и проверка новой сети
 * ([NetworkWatch], D-80).
 * Серверов нет, а список «Напрямую с разбиением» есть — туннель без сервера
 * (D-83). Раздача туннеля — на точке доступа ПК (D-84): вход прокси на её
 * адресах, смена набора — переподключение. Выбрано устройство раздачи —
 * подключение только через него (D-85). На Windows раздачи и устройств
 * раздачи нет (D-97): выбранное устройство — отказ с причиной.
 */
class DesktopSession(
    private val graph: DesktopGraph,
    private val scope: CoroutineScope,
    private val prefs: DesktopPrefs,
    private val shares: LinuxShareInterfaces? = graph.shares,
    private val notify: DesktopNotifier = graph.host.notifier,
    /** Сеть под туннелем для учёта трафика (D-92): маршрут по умолчанию мимо туннеля. */
    private val network: () -> NetworkType = { graph.host.network()?.type ?: NetworkType.NONE },
) {
    private val state = MutableStateFlow<SessionStatus>(SessionStatus.Disconnected)
    val status: StateFlow<SessionStatus> = state

    private val noticeState = MutableStateFlow<ServerNotice?>(null)

    /** Вопрос о замене сервера или сообщение о ней (D-58); null — нечего показывать. */
    val notice: StateFlow<ServerNotice?> = noticeState

    private val localState = MutableStateFlow<LocalProxySpec?>(null)

    /** Подключено без VPN (D-95): локальный прокси сеанса; через VPN или без подключения — null. */
    val localProxy: StateFlow<LocalProxySpec?> = localState

    private val shareState = MutableStateFlow<ShareStatus?>(null)

    /** Раздача сеанса (D-84); null — туннеля нет или раздача выключена. */
    val share: StateFlow<ShareStatus?> = shareState

    /** Опрос точки доступа под туннелем (D-84). */
    @Volatile
    private var shareWatch: Job? = null

    /** Серверы, о которых пользователь ответил «Остаться» (D-58): до отключения. */
    private val declined: MutableSet<ProfileId> = Collections.synchronizedSet(HashSet())

    @Volatile
    private var watch: Job? = null

    /** Смена сети под туннелем (D-80): опрос сети и проверка новой. */
    @Volatile
    private var networkWatch: Job? = null

    /** Смены сети — на всё время туннеля, с переподключениями (D-67): переподключение не отменяет проверку новой сети. */
    @Volatile
    private var changes: NetworkChangeChecks? = null

    /** Режим сессии (D-64): взят при подключении, заново — при смене сети (D-80). */
    @Volatile
    private var sessionRegime: NetworkAssessment? = null

    private val lock = Mutex()

    // Окно зовёт с потока EDT, автообновление (D-77) — из фона.
    @Volatile
    private var job: Job? = null

    @Volatile
    private var session: EngineSession? = null

    @Volatile
    private var tunnel: DesktopTunnel? = null

    /** Трафик сеанса; null — ядро не запущено. */
    fun traffic(): TrafficStats? = session?.stats()

    private val usageAlertState = MutableStateFlow<UsageAlert?>(null)

    /** Порог мобильной сети пройден (D-92) — полоса в окне до «Понятно». */
    val usageAlert: StateFlow<UsageAlert?> = usageAlertState

    fun dismissUsageAlert() {
        usageAlertState.value = null
    }

    /** Учёт трафика сеанса (D-92): опрос счётчиков и их приращения. */
    @Volatile
    private var usageTick: Job? = null

    @Volatile
    private var usageMeter: UsageMeter? = null

    fun connect(preferred: ProfileId?) {
        if (job?.isActive == true) return
        job = scope.launch { lock.withLock { connectNow(preferred) } }
    }

    /** Подключённый сервер; null — туннеля нет. */
    fun connectedProfile(): ProfileId? = (state.value as? SessionStatus.Connected)?.profileId

    /** Туннель есть — переподключить с новыми настройками (D-81); нет — ничего, они в силе со следующего подключения. */
    fun reconnectIfConnected() {
        if (session != null) reconnect(prefs.selectedServer)
    }

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
        // Ответ «Остаться» и вопрос — до отключения (D-58); смены сети — тоже (D-80).
        declined.clear()
        noticeState.value = null
        changes = null
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
        networkWatch?.cancel()
        shareWatch?.cancel()
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
        // Устройство раздачи (D-55, D-85): выбрано — подключение только через него, по адресу, где оно ответило.
        val relay = prefs.selectedRelay?.let(core.relays::find)
        val target = relay?.let { d ->
            val relays = graph.relayNetworks ?: return fail(
                Diagnostic.error(
                    DiagCode.CAPABILITY_FEATURE_UNSUPPORTED,
                    "устройств раздачи на Windows нет (D-97) — выбранное в настройках устройство здесь не подключить",
                ),
            )
            when (val t = withContext(Dispatchers.IO) { relays.locate(d) }) {
                is Outcome.Failure -> return fail(t.errors.first())
                is Outcome.Success -> t.value.also { core.log.info("relay_found", "medium" to Safe(it.medium.name), "auto" to (d.address == null)) }
            }
        }
        // Без VPN (D-95): локальный прокси вместо TUN — и прав на туннель не нужно; порт занят — новый.
        val local = when (val l = withContext(Dispatchers.IO) { core.localProxy.prepare() }) {
            is Outcome.Failure -> return fail(l.errors.first())
            is Outcome.Success -> l.value.also { l.diagnostics.forEach(core.log::diagnostic) }
        }
        // Без сервера (D-73, D-83): серверов нет, устройство не выбрано, а сайтам списка (или всем, с разбиением) нужен туннель.
        val serverless = prefs.serverless
        if (core.serverlessReady(prefs.splitSites(), serverless, relaySelected = relay != null)) {
            if (local != null) {
                val why = "серверов нет, а режим без сервера (D-73) работает только через VPN — без VPN подключаться не к чему"
                return fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, why))
            }
            return connectServerlessNow(prefs.splitSites(), serverless)
        }
        val ir = (if (relay != null && target != null) core.relayConfig(relay, target.address) else core.activation.state.activeConfig)
            ?: return fail(
                Diagnostic.error(
                    DiagCode.PROFILES_EMPTY,
                    "нет активной конфигурации — добавьте подписку или импортируйте серверы; без сервера туннелю нужны «Сайты напрямую с разбиением»",
                ),
            )
        // Через VPN — TUN и маршруты; без VPN (D-95) их нет.
        val spec = if (local != null) {
            null
        } else {
            when (val s = core.tunnelSpecFor(ir)) {
                is Outcome.Failure -> return fail(s.errors.first())
                is Outcome.Success -> s.value
            }
        }
        // Раздача (D-51, D-84) — только на точке доступа ПК; включена, а точки доступа нет — туннель без неё.
        // На Windows раздачи нет (D-97): окно её не показывает, а включённая раньше — не действует.
        val shareSettings = core.share.current().also { r -> r.diagnostics.forEach(core.log::diagnostic) }.valueOrNull()
        val finder = shares
        val scan = if (shareSettings?.enabled == true && finder != null) withContext(Dispatchers.IO) { finder.find() } else null
        if (scan != null && scan.endpoints.isEmpty()) core.log.info("share_no_tether", "seen" to Safe(scan.seen))
        val share = if (scan != null) shareSettings?.spec(scan.endpoints) else null
        val shareSubnets = share?.endpoints.orEmpty().map { it.subnet }
        val handle = spec?.let { tunSpec ->
            when (val t = withContext(Dispatchers.IO) { graph.tunnels.establish(tunSpec, shareSubnets) }) {
                is Outcome.Failure -> {
                    t.errors.drop(1).forEach(core.log::diagnostic)
                    return fail(t.errors.first())
                }
                is Outcome.Success -> t.value
            }
        }
        if (local != null) core.log.info("local_proxy_up", "port" to local.port)
        // Проба здоровья (D-32) блокирует поток — не дольше своего срока, меньше срока плана.
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, profile ->
            state.value = SessionStatus.Connecting(profile.name)
            withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, probeTimeout) }
        }
        // Белый список по свежей проверке в этой сети (D-64, D-79): порядок плана и опыт попыток — его.
        // Через устройство раздачи путь идёт по своей сети — режим оператора ни при чём (D-55).
        val regime = if (relay == null) graph.networkCheck.regime() else null
        regime?.let { core.log.info("network_regime", "class" to it.restriction) }
        val failingUnderRegime = regime?.let(core::failingUnder).orEmpty()
        val report = try {
            if (relay != null && target != null) {
                core.connectVia(relay, target.address, checker, handle?.tunInput, share, local) { delay(it) }
            } else {
                // Разбиение ClientHello к серверу (D-68, D-81) — выбор пользователя; отказ сервера — повтор без него (D-69, ядро).
                // К устройству раздачи — нет.
                val split = prefs.splitClientHello
                core.log.info("client_hello_split", "on" to split)
                // Сайты напрямую с разбиением (D-72, D-82): в журнал — число записей, не сами сайты.
                val sites = prefs.splitSites()
                core.log.info("split_sites", "n" to sites.size)
                core.connect(null, checker, handle?.tunInput, preferred, share, regime, split, sites, local, handle?.systemTun) { delay(it) }
            }
        } catch (e: CancellationException) {
            // Сеанс, запущенный посреди проверки, оркестратор уже остановил; остаётся TUN.
            withContext(NonCancellable + Dispatchers.IO) { handle?.close() }
            state.value = SessionStatus.Disconnected
            throw e
        }
        when (report) {
            is ConnectionReport.Connected -> {
                session = report.session
                tunnel = handle
                localState.value = local
                val name = ir.profiles.firstOrNull { it.id == report.profileId }?.name ?: report.profileId.value
                core.log.info("connected", "profile" to Safe(report.profileId.value), "attempts" to report.attempts.size)
                // Подключился сервер, который под белым списком только отказывал: список, скорее всего,
                // выключили — режим снова неизвестен (D-64).
                val contradicted = regime != null && report.profileId in failingUnderRegime
                if (contradicted) {
                    graph.networkCheck.forgetRegime()
                    core.log.info("network_regime_dropped", "reason" to Safe("contradicted"), "profile" to Safe(report.profileId.value))
                }
                // Режим сессии — до того, как наблюдение за сетью может взять его заново (D-80).
                sessionRegime = if (contradicted) null else regime
                state.value = SessionStatus.Connected(report.profileId, name, core.clock.nowMillis())
                startUsage(report.session)
                val profile = ir.profiles.firstOrNull { it.id == report.profileId }
                val w = SessionWatch(
                    core,
                    report.profileId,
                    profile,
                    { graph.engine.probeHealth(ir.dns, probeTimeout) },
                    { prefs.selectedServer },
                    { prefs.autoSwitch },
                    { synchronized(declined) { declined.toSet() } },
                    { sessionRegime },
                    graph.networkCheck::probesQuiet,
                )
                watch = scope.launch { onDegraded(withContext(Dispatchers.IO) { w.run { delay(it) } }) }
                // Через устройство раздачи режим сети не берётся (D-55): смена сети ПК ему не повод; пропала
                // сеть устройства — сбой ловит наблюдатель.
                if (relay == null) {
                    val net = NetworkWatch(
                        core.log,
                        graph.networkCheck,
                        changes ?: NetworkChangeChecks(Clock.MONOTONIC).also { changes = it },
                        { checkOnNetworkChange() },
                        { sessionRegime = it },
                        graph.host::network,
                    )
                    networkWatch = scope.launch(Dispatchers.IO) { net.run { delay(it) } }
                }
                if (scan != null) {
                    val offered = share?.endpoints.orEmpty()
                    val refused = report.shareRefused != null
                    shareState.value = ShareStatus(if (refused) emptyList() else offered, refused, scan.source)
                    core.log.info("share", "endpoints" to offered.size, "refused" to refused)
                    finder?.let { startShareWatch(it, offered) }
                }
            }
            is ConnectionReport.Failed -> {
                withContext(Dispatchers.IO) { handle?.close() }
                fail(report.reason)
            }
            null -> {
                withContext(Dispatchers.IO) { handle?.close() }
                fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — подключаться не к чему"))
            }
        }
    }

    /**
     * Без сервера (D-73, D-83): TUN для всех программ, ядро только с прямыми
     * выходами, проба DoH напрямую. Наблюдателя (D-78) нет — сервера нет;
     * смена сети (D-80) — как с сервером.
     */
    private suspend fun connectServerlessNow(sites: SplitSites, settings: ServerlessSettings) {
        val core = graph.core
        state.value = SessionStatus.Connecting(SERVERLESS_NAME)
        val spec = when (val s = core.tunnelSpecFor(core.serverlessConfig(settings))) {
            is Outcome.Failure -> return fail(s.errors.first())
            is Outcome.Success -> s.value
        }
        val handle = when (val t = withContext(Dispatchers.IO) { graph.tunnels.establish(spec, emptyList()) }) {
            is Outcome.Failure -> {
                t.errors.drop(1).forEach(core.log::diagnostic)
                return fail(t.errors.first())
            }
            is Outcome.Success -> t.value
        }
        core.log.info("split_sites", "n" to sites.size)
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val result = try {
            core.connectServerless(handle.tunInput, sites, settings, handle.systemTun) { _, dns ->
                withContext(Dispatchers.IO) { graph.engine.probeServerless(dns, probeTimeout) }
            }
        } catch (e: CancellationException) {
            withContext(NonCancellable + Dispatchers.IO) { handle.close() }
            state.value = SessionStatus.Disconnected
            throw e
        }
        when (result) {
            is Outcome.Failure -> {
                withContext(Dispatchers.IO) { handle.close() }
                fail(result.errors.first())
            }
            is Outcome.Success -> {
                session = result.value
                tunnel = handle
                core.log.info("connected", "profile" to Safe(ServerlessPlan.PROFILE_ID.value), "attempts" to 1)
                // Режима сессии без сервера нет: опыт не копится — его не у кого.
                sessionRegime = null
                state.value = SessionStatus.Connected(ServerlessPlan.PROFILE_ID, SERVERLESS_NAME, core.clock.nowMillis())
                val net = NetworkWatch(
                    core.log,
                    graph.networkCheck,
                    changes ?: NetworkChangeChecks(Clock.MONOTONIC).also { changes = it },
                    { checkOnNetworkChange() },
                    { sessionRegime = it },
                    graph.host::network,
                )
                networkWatch = scope.launch(Dispatchers.IO) { net.run { delay(it) } }
            }
        }
    }

    /**
     * Раздача (D-84): набор адресов точки доступа сменился — переподключение;
     * остановка сеанса отменяет опрос, и переподключения нет.
     */
    private fun startShareWatch(finder: LinuxShareInterfaces, current: List<ShareSpec.Endpoint>) {
        val w = ShareWatch(graph.core.log, current) { finder.find().endpoints }
        shareWatch = scope.launch {
            withContext(Dispatchers.IO) { w.run { delay(it) } }
            reconnect(prefs.selectedServer)
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

    /** Приращения счётчиков ядра — в учёт трафика (D-92), раз в [USAGE_TICK_MILLIS]. */
    private fun startUsage(s: EngineSession) {
        usageTick?.cancel()
        val meter = UsageMeter().also { usageMeter = it }
        usageTick = scope.launch(Dispatchers.IO) {
            while (true) {
                delay(USAGE_TICK_MILLIS)
                recordUsage(s, meter)
            }
        }
    }

    private fun recordUsage(s: EngineSession, meter: UsageMeter) {
        val alert = graph.core.usage.record(meter.delta(s.stats()), network()) ?: return
        usageAlertState.value = alert
        val shown = notify.show(UsageText.ALERT_TITLE, UsageText.alert(alert))
        graph.core.log.info("usage_alert", "used" to alert.usedBytes, "limit" to alert.limitBytes, "desktop_notification" to shown)
    }

    private suspend fun stopNow() {
        // Учёт трафика (D-92): последние секунды сеанса — до остановки ядра, и всё — на диск.
        usageTick?.cancel()
        usageTick = null
        val meter = usageMeter
        usageMeter = null
        session?.let { s -> meter?.let { m -> withContext(Dispatchers.IO) { recordUsage(s, m) } } }
        withContext(NonCancellable + Dispatchers.IO) { graph.core.usage.flush().diagnostics.forEach(graph.core.log::diagnostic) }
        watch?.cancel()
        watch = null
        networkWatch?.cancel()
        networkWatch = null
        shareWatch?.cancel()
        shareWatch = null
        shareState.value = null
        localState.value = null
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

    /** Проверка после смены сети (D-80): выбор пользователя — там, где пробы идут мимо туннеля (на Windows нет, D-97). */
    private fun checkOnNetworkChange(): Boolean = prefs.checkOnNetworkChange && graph.host.checksUnderTunnel

    private fun fail(reason: Diagnostic) {
        graph.core.log.diagnostic(reason)
        state.value = SessionStatus.Failed(reason)
    }

    private companion object {
        const val PROBE_MARGIN_MILLIS = 2_000L

        /** Опрос счётчиков для учёта трафика: на ПК экрана, который гаснет, нет — реже, чем окно. */
        const val USAGE_TICK_MILLIS = 5_000L

        /** Имя сеанса без сервера в окне (D-83), как на телефоне. */
        const val SERVERLESS_NAME = "Без сервера"
    }
}
