package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.config.ConfigIr
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
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
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

    /**
     * Туннель стоит, а соединения нет (D-115): сеть пропала, идёт восстановление
     * или сервер не отвечает. Весь трафик заблокирован до восстановления или
     * «Отключить»; сервер — [server], сам он не меняется. [attempts] — сколько
     * попыток уже не удалось, [reason] — причина последней.
     */
    data class Blocked(
        val profileId: ProfileId,
        val server: String,
        val why: BlockReason,
        val attempts: Int = 0,
        val reason: Diagnostic? = null,
    ) : SessionStatus
}

/** Почему туннель стоит без соединения (D-115). */
enum class BlockReason {
    /** Сети ПК нет: ждём её. */
    NO_NETWORK,

    /** Сеть есть: соединяемся с тем же сервером. */
    RECONNECTING,

    /** Сеть есть, а сервер не отвечает: попытки идут дальше по расписанию. */
    UNREACHABLE,
}

/**
 * Сбой сервера сеанса (D-58, D-78): [asked] — вопрос, перейти ли с [from] на
 * [to]; иначе — сообщение, что DPpass перешёл сам (автопереключение).
 * [unreachable] — соединение не восстановилось за несколько попыток (D-115):
 * трафик заблокирован, сервер сам не меняется; [to] — замена, которую можно
 * предложить (null — предложить нечего, тогда и [asked] — false).
 */
data class ServerNotice(
    val from: ServerProfile,
    val to: ServerProfile?,
    val reason: Diagnostic,
    val asked: Boolean,
    val unreachable: Boolean = false,
)

/**
 * Раздача сеанса для окна (D-84): на каких адресах точки доступа открыт вход;
 * [refused] — ядро не открыло вход, и туннель работает без раздачи;
 * [absent] — почему точки доступа не нашлось, по словам системы (D-84, D-101).
 */
data class ShareStatus(val endpoints: List<ShareSpec.Endpoint>, val refused: Boolean, val absent: String)

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
 * (D-83). Раздача туннеля — на точке доступа ПК (D-84, на Windows — частная
 * сторона ICS, D-101): вход прокси на её адресах, смена набора —
 * переподключение. Выбрано устройство раздачи — подключение только через
 * него (D-85; на Windows сокеты ядра — к интерфейсу сети, где оно
 * ответило, D-102).
 *
 * Автопереключение выключено (D-115, как D-113 на Android) — сервер сеанса
 * закреплён: подключение и переподключение пробуют только его. Сеть ПК
 * пропала или сервер перестал отвечать — туннель не снимается, весь трафик
 * заблокирован ([SessionStatus.Blocked]), а [SessionRecovery] ждёт сеть и
 * восстанавливает соединение тем же сервером: на Linux ядро перезапускается
 * при прежнем TUN и правилах, на Windows (адаптер живёт с ядром) ядро не
 * останавливается. Не вышло — сообщение с предложением сменить сервер или
 * перезапустить подключение; сам сервер не меняется.
 */
class DesktopSession(
    private val graph: DesktopGraph,
    private val scope: CoroutineScope,
    private val prefs: DesktopPrefs,
    private val shares: DesktopShares? = graph.shares,
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

    /** Сеанс включён: подключились, и пользователь не отключил — даже если ядро сейчас стоит (D-115). */
    @Volatile
    private var on = false

    /** Сервер и конфигурация сеанса: для наблюдателя и восстановления (D-115); null — сеанса с сервером нет. */
    @Volatile
    private var current: Current? = null

    /** Сервер, закреплённый при «Автоматически» и выключенном автопереключении (D-115): тот, к которому подключились. */
    @Volatile
    private var pin: ServerPin.Pin? = null

    /** Восстановление соединения (D-115). */
    @Volatile
    private var recovery: Job? = null

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

    /** Сервер сеанса; null — туннеля нет. Пока туннель стоит без соединения (D-115) — тоже он. */
    fun connectedProfile(): ProfileId? = when (val s = state.value) {
        is SessionStatus.Connected -> s.profileId
        is SessionStatus.Blocked -> s.profileId
        else -> null
    }

    /** Туннель есть — переподключить с новыми настройками (D-81); нет — ничего, они в силе со следующего подключения. */
    fun reconnectIfConnected() {
        if (on) reconnect(prefs.selectedServer)
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
            stopRecovery()
            lock.withLock {
                if (!on) return@withLock
                stopNow()
                connectNow(preferred)
            }
        }
    }

    /**
     * «Перейти» (D-58): замена — только из действующей конфигурации, иначе — с
     * прежним выбором. Где можно, туннель не снимается (D-115): ядро заново,
     * уже с новым сервером, и трафик мимо VPN не уходит и на это время.
     */
    fun acceptSwitch() {
        val n = noticeState.value?.takeIf { it.asked } ?: return
        val to = n.to ?: return
        noticeState.value = null
        val core = graph.core
        if (core.activation.state.activeConfig?.profiles?.any { it.id == to.id } == true) {
            prefs.selectedServer = to.id
            core.log.info("server_switched", "from" to Safe(n.from.id.value), "to" to Safe(to.id.value), "by" to Safe("user"))
        } else {
            core.log.info("server_switch_stale")
        }
        // Выбор пользователя — новый сервер: прежнее закрепление ни к чему (D-115).
        pin = null
        restart()
    }

    /**
     * «Перезапустить подключение» (D-115): ядро заново, сразу, без паузы
     * восстановления. На Linux TUN и правила остаются — трафик заблокирован и
     * на время перезапуска; на Windows адаптер уходит вместе с ядром, и это
     * обычное переподключение.
     */
    fun restartConnection() {
        noticeState.value = null
        graph.core.log.info("connection_restart", "by" to Safe("user"))
        restart()
    }

    private fun restart() {
        if (!canRestartInPlace()) {
            if (on) reconnect(prefs.selectedServer) else connect(prefs.selectedServer)
            return
        }
        val running = job
        job = scope.launch {
            running?.cancel()
            running?.join()
            stopRecovery()
            lock.withLock {
                val ctx = current?.let(::retarget)
                if (!on || ctx == null) return@withLock
                state.value = SessionStatus.Blocked(ctx.profileId, ctx.name, BlockReason.RECONNECTING)
                restartInPlace()?.let { failed ->
                    state.value = SessionStatus.Blocked(ctx.profileId, ctx.name, BlockReason.UNREACHABLE, 1, failed)
                    startRecovery(failed, failedBefore = 1)
                }
            }
        }
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
        // Ответ «Остаться» и вопрос — до отключения (D-58); смены сети — тоже (D-80); закрепление сервера — тоже (D-115).
        declined.clear()
        noticeState.value = null
        changes = null
        pin = null
        val running = job
        scope.launch {
            running?.cancel()
            running?.join()
            stopRecovery()
            lock.withLock { stopNow() }
        }
    }

    /**
     * Выход процесса: без корутин и блокировок — поток `Runtime.addShutdownHook`.
     * Ядро останавливается мостом напрямую, затем TUN и правила.
     */
    fun shutdownNow() {
        recovery?.cancel()
        watch?.cancel()
        networkWatch?.cancel()
        shareWatch?.cancel()
        if (session != null) graph.runtime?.stop()
        tunnel?.close()
        session = null
        tunnel = null
        on = false
        // Опыт адаптивной модели — на диск (D-44).
        graph.core.persistStability()
    }

    /**
     * Подключить. [recovering] — восстановление (D-115): туннель уже стоит
     * ([tunnel]; без VPN его нет) — не поднимать его и при отказе не снимать;
     * окно ведёт восстановление. Отказ — причина; подключено — null.
     */
    private suspend fun connectNow(preferred: ProfileId?, recovering: Boolean = false): Diagnostic? {
        if (session != null) return null
        val core = graph.core
        if (!recovering) state.value = SessionStatus.Connecting(null)
        // Устройство раздачи (D-55, D-85): выбрано — подключение только через него, по адресу, где оно ответило.
        // Восстановление (D-115) через устройство не идёт: у него путь свой.
        val relay = if (recovering) null else prefs.selectedRelay?.let(core.relays::find)
        val target = relay?.let { d ->
            val relays = graph.relayNetworks ?: return refuse(
                recovering,
                Diagnostic.error(
                    DiagCode.CAPABILITY_FEATURE_UNSUPPORTED,
                    "без библиотеки ядра DPpass сетей ПК не узнать — выбранное в настройках устройство раздачи здесь не подключить",
                ),
            )
            when (val t = withContext(Dispatchers.IO) { relays.locate(d) }) {
                is Outcome.Failure -> return refuse(recovering, t.errors.first())
                is Outcome.Success -> t.value.also { core.log.info("relay_found", "medium" to Safe(it.medium.name), "auto" to (d.address == null)) }
            }
        }
        // Без VPN (D-95): локальный прокси вместо TUN — и прав на туннель не нужно; порт занят — новый.
        val local = when (val l = withContext(Dispatchers.IO) { core.localProxy.prepare() }) {
            is Outcome.Failure -> return refuse(recovering, l.errors.first())
            is Outcome.Success -> l.value.also { l.diagnostics.forEach(core.log::diagnostic) }
        }
        // Восстановление — только тем же путём, что и сеанс: TUN стоит — через него, без VPN — без него.
        if (recovering && (local == null) != (tunnel != null)) {
            val why = "режим подключения сменился — нужно переподключение, а не восстановление"
            return refuse(recovering, Diagnostic.error(DiagCode.TUN_ESTABLISH_FAILED, why))
        }
        // Без сервера (D-73, D-83): серверов нет, устройство не выбрано, а сайтам списка (или всем, с разбиением) нужен туннель.
        val serverless = prefs.serverless
        if (!recovering && core.serverlessReady(prefs.splitSites(), serverless, relaySelected = relay != null)) {
            if (local != null) {
                val why = "серверов нет, а режим без сервера (D-73) работает только через VPN — без VPN подключаться не к чему"
                return refuse(recovering, Diagnostic.error(DiagCode.PROFILES_EMPTY, why))
            }
            connectServerlessNow(prefs.splitSites(), serverless)
            return (state.value as? SessionStatus.Failed)?.reason
        }
        val ir = (if (relay != null && target != null) core.relayConfig(relay, target.address) else core.activation.state.activeConfig)
            ?: return refuse(
                recovering,
                Diagnostic.error(
                    DiagCode.PROFILES_EMPTY,
                    "нет активной конфигурации — добавьте подписку или импортируйте серверы; без сервера туннелю нужны «Сайты напрямую с разбиением»",
                ),
            )
        // Через VPN — TUN и маршруты; без VPN (D-95) их нет; восстановление — при прежнем TUN.
        val spec = if (local != null || recovering) {
            null
        } else {
            when (val s = core.tunnelSpecFor(ir)) {
                is Outcome.Failure -> return refuse(recovering, s.errors.first())
                is Outcome.Success -> s.value
            }
        }
        // Раздача (D-51, D-84) — только на точке доступа ПК; включена, а точки доступа нет — туннель без неё.
        // Без библиотеки моста на Windows точку доступа не узнать (D-101): окно раздачу не показывает, а включённая раньше — не действует.
        val shareSettings = core.share.current().also { r -> r.diagnostics.forEach(core.log::diagnostic) }.valueOrNull()
        val finder = shares
        val scan = if (shareSettings?.enabled == true && finder != null) withContext(Dispatchers.IO) { finder.find() } else null
        if (scan != null && scan.endpoints.isEmpty()) core.log.info("share_no_tether", "seen" to Safe(scan.seen))
        val share = if (scan != null) shareSettings?.spec(scan.endpoints) else null
        val shareSubnets = share?.endpoints.orEmpty().map { it.subnet }
        val pending = PendingTunnel()
        try {
            val handle = if (recovering) {
                tunnel
            } else {
                spec?.let { tunSpec ->
                    when (val t = pending.acquire { graph.tunnels.establish(tunSpec, shareSubnets, target?.iface) }) {
                        is Outcome.Failure -> {
                            t.errors.drop(1).forEach(core.log::diagnostic)
                            return refuse(recovering, t.errors.first())
                        }
                        is Outcome.Success -> t.value
                    }
                }
            }
            currentCoroutineContext().ensureActive()
            if (local != null) core.log.info("local_proxy_up", "port" to local.port)
            // Проба здоровья (D-32) блокирует поток — не дольше своего срока, меньше срока плана.
            val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
            val checker = HealthChecker { _, profile ->
                if (!recovering) state.value = SessionStatus.Connecting(profile.name)
                withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, probeTimeout) }
            }
            // Белый список по свежей проверке в этой сети (D-64, D-79): порядок плана и опыт попыток — его.
            // Через устройство раздачи путь идёт по своей сети — режим оператора ни при чём (D-55).
            val regime = if (relay == null) graph.networkCheck.regime() else null
            regime?.let { core.log.info("network_regime", "class" to it.restriction) }
            val failingUnderRegime = regime?.let(core::failingUnder).orEmpty()
            val report = if (relay != null && target != null) {
                core.connectVia(relay, target.address, checker, handle?.tunInput, share, local, handle?.systemTun) { delay(it) }
            } else {
                // Разбиение ClientHello к серверу (D-68, D-81) — выбор пользователя; отказ сервера — повтор без него (D-69, ядро).
                // К устройству раздачи — нет.
                val split = prefs.splitClientHello
                core.log.info("client_hello_split", "on" to split)
                // Сайты напрямую с разбиением (D-72, D-82): в журнал — число записей, не сами сайты.
                val sites = prefs.splitSites()
                core.log.info("split_sites", "n" to sites.size)
                // Автопереключение выключено (D-115, D-113): сервер, который держит сеанс, не меняется сам — пробуется только он.
                val strict = pinTarget()
                if (strict != null) core.log.info("server_pinned", "profile" to Safe(strict.value))
                val first = strict ?: preferred
                val tun = handle?.tunInput
                core.connect(null, checker, tun, first, share, regime, split, sites, local, handle?.systemTun, pinned = strict != null) { delay(it) }
            }
            when (report) {
                is ConnectionReport.Connected -> {
                    val previous = current
                    session = report.session
                    if (!recovering) tunnel = pending.take()
                    on = true
                    localState.value = local
                    val profile = ir.profiles.firstOrNull { it.id == report.profileId }
                    val name = profile?.name ?: report.profileId.value
                    core.log.info("connected", "profile" to Safe(report.profileId.value), "attempts" to report.attempts.size, "recovering" to recovering)
                    // Автопереключение выключено: держим именно этот сервер, пока пользователь не выберет другой (D-115).
                    if (relay == null && !prefs.autoSwitch) pin = ServerPin.Pin(report.profileId, prefs.selectedServer)
                    // Восстановление с согласием на замену (автопереключение включено) подключило другой сервер — сказать (D-58).
                    val from = previous?.profile
                    if (recovering && from != null && profile != null && from.id != profile.id) {
                        val why = Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "«${from.name}» не ответил, когда DPpass восстанавливал соединение")
                        noticeState.value = ServerNotice(from, profile, why, asked = false)
                        core.log.info("server_switched", "from" to Safe(from.id.value), "to" to Safe(profile.id.value), "by" to Safe("auto"))
                    }
                    // Подключился сервер, который под белым списком только отказывал: список, скорее всего,
                    // выключили — режим снова неизвестен (D-64).
                    val contradicted = regime != null && report.profileId in failingUnderRegime
                    if (contradicted) {
                        graph.networkCheck.forgetRegime()
                        core.log.info("network_regime_dropped", "reason" to Safe("contradicted"), "profile" to Safe(report.profileId.value))
                    }
                    // Режим сессии — до того, как наблюдение за сетью может взять его заново (D-80).
                    sessionRegime = if (contradicted) null else regime
                    val ctx = Current(ir, report.profileId, profile, name, probeTimeout, viaRelay = relay != null)
                    current = ctx
                    state.value = SessionStatus.Connected(report.profileId, name, core.clock.nowMillis())
                    startUsage(report.session)
                    startWatch(ctx)
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
                        shareState.value = ShareStatus(if (refused) emptyList() else offered, refused, scan.absent)
                        core.log.info("share", "endpoints" to offered.size, "refused" to refused)
                        finder?.let { startShareWatch(it, offered) }
                    }
                    return null
                }
                is ConnectionReport.Failed -> {
                    return refuse(recovering, report.reason)
                }
                null -> {
                    return refuse(recovering, Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — подключаться не к чему"))
                }
            }
        } catch (e: CancellationException) {
            if (!recovering) state.value = SessionStatus.Disconnected
            throw e
        } finally {
            pending.closeUnclaimed()
        }
    }

    /** Отказ подключения: при восстановлении (D-115) — только в журнал, туннель и окно — у восстановления. */
    private fun refuse(recovering: Boolean, reason: Diagnostic): Diagnostic {
        if (recovering) graph.core.log.diagnostic(reason) else fail(reason)
        return reason
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
        val pending = PendingTunnel()
        try {
            val handle = when (val t = pending.acquire { graph.tunnels.establish(spec, emptyList(), null) }) {
                is Outcome.Failure -> {
                    t.errors.drop(1).forEach(core.log::diagnostic)
                    return fail(t.errors.first())
                }
                is Outcome.Success -> t.value
            }
            currentCoroutineContext().ensureActive()
            core.log.info("split_sites", "n" to sites.size)
            val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
            val result = core.connectServerless(handle.tunInput, sites, settings, handle.systemTun) { _, dns ->
                withContext(Dispatchers.IO) { graph.engine.probeServerless(dns, probeTimeout) }
            }
            when (result) {
                is Outcome.Failure -> {
                    fail(result.errors.first())
                }
                is Outcome.Success -> {
                    session = result.value
                    tunnel = pending.take()
                    on = true
                    // Сервера нет — восстанавливать соединение не с кем (D-115): наблюдателя нет, как и прежде.
                    current = null
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
        } catch (e: CancellationException) {
            state.value = SessionStatus.Disconnected
            throw e
        } finally {
            pending.closeUnclaimed()
        }
    }

    /**
     * Раздача (D-84): набор адресов точки доступа сменился — переподключение;
     * остановка сеанса отменяет опрос, и переподключения нет.
     */
    private fun startShareWatch(finder: DesktopShares, current: List<ShareSpec.Endpoint>) {
        val w = ShareWatch(graph.core.log, current) { finder.find().endpoints }
        shareWatch = scope.launch {
            withContext(Dispatchers.IO) { w.run { delay(it) } }
            reconnect(prefs.selectedServer)
        }
    }

    /** Наблюдатель сеанса (D-78): пробы через сервер; пропажа сети и подтверждённый сбой — [onWatch]. */
    private fun startWatch(ctx: Current) {
        val w = SessionWatch(
            graph.core,
            ctx.profileId,
            ctx.profile,
            { graph.engine.probeHealth(ctx.ir.dns, ctx.probeTimeout) },
            // Закреплённый сервер (D-115) — тот, о замене которого спрашивать.
            { pinTarget() ?: prefs.selectedServer },
            { prefs.autoSwitch },
            { synchronized(declined) { declined.toSet() } },
            { sessionRegime },
            graph.networkCheck::probesQuiet,
            // Через устройство раздачи сеть своя (D-55): «сеть ПК пропала» к нему не относится.
            networkUp = if (ctx.viaRelay) ({ true }) else ::networkUp,
        )
        watch = scope.launch { onWatch(ctx, withContext(Dispatchers.IO) { w.run { delay(it) } }) }
    }

    private fun onWatch(ctx: Current, end: SessionWatch.End) {
        when (end) {
            SessionWatch.End.NetworkLost -> startRecovery(null)
            is SessionWatch.End.Degraded -> onDegraded(ctx, end.decision)
        }
    }

    /**
     * Сбой подтверждён (D-58): вопрос или замена. Туннель не снимается
     * (D-115): ядро заново при прежнем TUN — тем же сервером при выключенном
     * автопереключении, по плану при включённом. Через устройство раздачи и
     * там, где ядро не перезапустить при прежнем туннеле (Windows), замена — как
     * прежде, переподключением.
     */
    private fun onDegraded(ctx: Current, d: Degradation) {
        val log = graph.core.log
        when (d) {
            is Degradation.Reconnect -> Unit
            is Degradation.Ask -> {
                noticeState.value = ServerNotice(d.from, d.to, d.reason, asked = true)
                log.info("server_switch_offered", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value))
            }
            is Degradation.Switch -> {
                prefs.selectedServer = d.to.id
                pin = null
                noticeState.value = ServerNotice(d.from, d.to, d.reason, asked = false)
                log.info("server_switched", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value), "by" to Safe("auto"))
            }
        }
        if (ctx.viaRelay || (d is Degradation.Switch && !canRestartInPlace())) {
            // Пока на вопрос нет ответа — к прежнему выбору, как на Android.
            reconnect(prefs.selectedServer)
            return
        }
        if (d is Degradation.Switch) retarget(ctx)
        startRecovery(d.reason)
    }

    /**
     * Восстановление (D-115): сети нет — ждать её, трафик заблокирован; есть —
     * проба, затем ядро заново тем же сервером ([SessionRecovery]). [degraded] —
     * сбой сервера уже подтверждён; [failedBefore] — попыток уже не удалось.
     */
    private fun startRecovery(degraded: Diagnostic?, failedBefore: Int = 0) {
        if (recovery?.isActive == true) return
        val core = graph.core
        var told = false
        val events = object : SessionRecovery.Events {
            override fun waitingNetwork() {
                val ctx = current ?: return
                state.value = SessionStatus.Blocked(ctx.profileId, ctx.name, BlockReason.NO_NETWORK)
                val shown = notify.show(NO_NETWORK_TITLE, "VPN не отключён, сервер «${ctx.name}» прежний: соединение восстановится, когда сеть вернётся.")
                told = true
                core.log.info("network_lost_notified", "desktop_notification" to shown)
            }

            override fun attempting(attempt: Int) {
                val ctx = current ?: return
                val before = state.value as? SessionStatus.Blocked
                state.value = SessionStatus.Blocked(ctx.profileId, ctx.name, BlockReason.RECONNECTING, attempt - 1, before?.reason)
            }

            override fun failed(reason: Diagnostic, attempts: Int) {
                val ctx = current ?: return
                state.value = SessionStatus.Blocked(ctx.profileId, ctx.name, BlockReason.UNREACHABLE, attempts, reason)
            }

            override fun unreachable(reason: Diagnostic, attempts: Int) {
                offerChange(reason)
                told = true
            }
        }
        val restart: (suspend () -> Outcome<Unit>)? = if (canRestartInPlace()) {
            { lock.withLock { restartInPlace() }?.let { Outcome.failure(it) } ?: Outcome.Success(Unit) }
        } else {
            null
        }
        val r = SessionRecovery(core.log, ::networkUp, ::probeNow, restart, events)
        recovery = scope.launch {
            r.run({ delay(it) }, degraded, failedBefore)
            lock.withLock { resumeAfterRecovery() }
            val ctx = current
            if (told && ctx != null) {
                val shown = notify.show(RESTORED_TITLE, "Сервер «${ctx.name}»: трафик снова идёт через VPN.")
                core.log.info("recovery_notified", "desktop_notification" to shown)
            }
        }
    }

    private suspend fun stopRecovery() {
        val r = recovery ?: return
        recovery = null
        r.cancelAndJoin()
    }

    /** Ядро заново при прежнем туннеле (D-115): сервер — закреплённый или по выбору. Под [lock]. Отказ — причина. */
    private suspend fun restartInPlace(): Diagnostic? {
        // Пользователь мог выбрать другой сервер, пока туннель стоял без соединения: пробуется он.
        val ctx = current?.let(::retarget)
        if (!on || ctx == null) return Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "туннель отключён — восстанавливать нечего")
        stopCore()
        return connectNow(prefs.selectedServer ?: ctx.profileId, recovering = true)
    }

    /** Восстановлено: перезапуск всё запустил сам; после удачной пробы ядро работало — вернуть окно и наблюдатель. */
    private fun resumeAfterRecovery() {
        val ctx = current ?: return
        if (!on || session == null || watch?.isActive == true) return
        state.value = SessionStatus.Connected(ctx.profileId, ctx.name, graph.core.clock.nowMillis())
        startWatch(ctx)
    }

    /** Проба через работающее ядро (D-32); null — ядро сейчас не работает. */
    private suspend fun probeNow(): Outcome<Unit>? {
        val ctx = current ?: return null
        if (session == null) return null
        return withContext(Dispatchers.IO) { graph.engine.probeHealth(ctx.ir.dns, ctx.probeTimeout) }
    }

    /** Есть ли сеть ПК под туннелем (D-115): маршрут по умолчанию мимо него, как у [NetworkWatch]. */
    private fun networkUp(): Boolean = graph.host.network() != null

    /** Сервер, который сеанс обязан держать (D-115): [ServerPin]. */
    private fun pinTarget(): ProfileId? =
        ServerPin.target(prefs.autoSwitch, prefs.selectedServer, pin, graph.core.activation.state.activeConfig?.profiles?.map { it.id }.orEmpty())

    /** Можно ли перезапустить ядро, не снимая туннель (D-115): сеанс с сервером, TUN с fd платформы или без VPN. */
    private fun canRestartInPlace(): Boolean {
        val ctx = current ?: return false
        return on && !ctx.viaRelay && (tunnel?.outlivesCore ?: true)
    }

    /** Сервер сеанса — тот, что теперь выбран (замена по ответу или с согласием). */
    private fun retarget(ctx: Current): Current {
        val id = pinTarget() ?: prefs.selectedServer ?: return ctx
        if (id == ctx.profileId) return ctx
        val p = graph.core.activation.state.activeConfig?.profiles?.firstOrNull { it.id == id } ?: return ctx
        return ctx.copy(profileId = id, profile = p, name = p.name).also { current = it }
    }

    /**
     * Соединение не восстановилось за [SessionRecovery.NOTIFY_AFTER] попыток при
     * живой сети (D-115): сообщить. Сервер не меняется: замена — вопросом, если
     * она есть и пользователь не ответил «Остаться»; перезапуск — кнопкой.
     */
    private fun offerChange(reason: Diagnostic) {
        val core = graph.core
        val ctx = current
        val from = ctx?.let { c -> core.activation.state.activeConfig?.profiles?.firstOrNull { it.id == c.profileId } ?: c.profile }
        val to = from?.takeIf { it.id !in synchronized(declined) { declined.toSet() } }?.let { core.alternativeTo(it.id, sessionRegime) }
        if (from != null) noticeState.value = ServerNotice(from, to, reason, asked = to != null, unreachable = true)
        val name = from?.name ?: ctx?.name ?: "сервер сеанса"
        val next = to?.let { "Перейти на «${it.name}» или перезапустить подключение" } ?: "Перезапустить подключение или выбрать другой сервер"
        val shown = notify.show(
            UNREACHABLE_TITLE,
            "«$name»: ${reason.message}. Трафик заблокирован, DPpass пробует снова — сервер сам не сменится. $next — в окне DPpass.",
        )
        core.log.info("server_unreachable_notified", "profile" to Safe(from?.id?.value ?: "-"), "offer" to (to != null), "desktop_notification" to shown)
    }

    /** Приращения счётчиков ядра — в учёт трафика (D-92), раз в [USAGE_TICK_MILLIS]. */
    private fun startUsage(s: EngineSession) {
        usageTick?.cancel()
        val meter = UsageMeter().also { usageMeter = it }
        usageTick = scope.launch(Dispatchers.IO) {
            var ticks = 0L
            while (true) {
                delay(USAGE_TICK_MILLIS)
                recordUsage(s, meter)
                // Журнал уникальных соединений (D-106) — и с закрытой вкладкой: раз в 10 с, пока он включён.
                if (++ticks % ANALYZER_EVERY_TICKS == 0L && graph.core.analyzer.settings().let { it.enabled && it.keepUnique }) {
                    graph.core.analyzer.poll(graph.owners)
                }
            }
        }
    }

    private fun recordUsage(s: EngineSession, meter: UsageMeter) {
        val alert = graph.core.usage.record(meter.delta(s.stats()), network()) ?: return
        usageAlertState.value = alert
        val shown = notify.show(UsageText.ALERT_TITLE, UsageText.alert(alert))
        graph.core.log.info("usage_alert", "used" to alert.usedBytes, "limit" to alert.limitBytes, "desktop_notification" to shown)
    }

    /**
     * Остановить ядро, оставив туннель (D-115): трафик сеанса — в учёт, наблюдатели —
     * стоп. TUN, маршруты и правила снимает только [stopNow].
     */
    private suspend fun stopCore() {
        // Учёт трафика (D-92): последние секунды сеанса — до остановки ядра, и всё — на диск.
        usageTick?.cancel()
        usageTick = null
        val meter = usageMeter
        usageMeter = null
        session?.let { s -> meter?.let { m -> withContext(Dispatchers.IO) { recordUsage(s, m) } } }
        withContext(NonCancellable + Dispatchers.IO) {
            graph.core.usage.flush().diagnostics.forEach(graph.core.log::diagnostic)
            graph.core.analyzer.flush().diagnostics.forEach(graph.core.log::diagnostic)
        }
        watch?.cancel()
        watch = null
        networkWatch?.cancel()
        networkWatch = null
        shareWatch?.cancel()
        shareWatch = null
        shareState.value = null
        val s = session ?: return
        withContext(NonCancellable) { s.stop() }
        session = null
        withContext(NonCancellable + Dispatchers.IO) { graph.core.persistStability() }
    }

    private suspend fun stopNow() {
        // Туннель может стоять и без ядра — восстановление не удалось (D-115): снять и его.
        val held = session != null || tunnel != null
        if (held) state.value = SessionStatus.Disconnecting
        stopCore()
        localState.value = null
        current = null
        on = false
        if (!held) {
            if (state.value !is SessionStatus.Failed) state.value = SessionStatus.Disconnected
            return
        }
        withContext(NonCancellable + Dispatchers.IO) { tunnel?.close() }
        tunnel = null
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

        /** Опрос анализатора для журнала уникальных (D-106): раз в 2 тика учёта, то есть в 10 с. */
        private const val ANALYZER_EVERY_TICKS = 2L

        /** Имя сеанса без сервера в окне (D-83), как на телефоне. */
        const val SERVERLESS_NAME = "Без сервера"

        /** Заголовки уведомлений восстановления (D-115). */
        const val NO_NETWORK_TITLE = "Нет сети — трафик заблокирован"
        const val UNREACHABLE_TITLE = "Нет соединения с сервером"
        const val RESTORED_TITLE = "Соединение восстановлено"
    }

    /** Сеанс с сервером (D-115): конфигурация, сервер и срок пробы — для наблюдателя и восстановления. */
    private data class Current(
        val ir: ConfigIr,
        val profileId: ProfileId,
        val profile: ServerProfile?,
        val name: String,
        val probeTimeout: Int,
        val viaRelay: Boolean,
    )
}
