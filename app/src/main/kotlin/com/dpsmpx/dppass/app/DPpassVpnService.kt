package com.dpsmpx.dppass.app

import android.app.ForegroundServiceStartNotAllowedException
import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.graphics.drawable.Icon
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.PowerManager
import android.service.quicksettings.TileService
import com.dpsmpx.dppass.R
import com.dpsmpx.dppass.app.ui.Formats
import com.dpsmpx.dppass.app.alpine.AlpineFiles
import com.dpsmpx.dppass.app.alpine.AlpinePlannerSelection
import com.dpsmpx.dppass.app.alpine.AlpineZapret2Runtime
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.ServerlessSettings
import com.dpsmpx.dppass.connection.Zapret2Backend
import com.dpsmpx.dppass.connection.Zapret2Hostlist
import com.dpsmpx.dppass.connection.SessionSupervisor
import com.dpsmpx.dppass.connection.StabilityObservation
import com.dpsmpx.dppass.connection.UsageMeter
import com.dpsmpx.dppass.connection.toTunInput
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.DesyncTrick
import com.dpsmpx.dppass.engine.Zapret2Stages
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.xray.Ipv6Egress
import com.dpsmpx.dppass.engine.xray.JniXrayRuntime
import com.dpsmpx.dppass.engine.xray.XrayResult
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.RestrictionClass
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.tunnel.Ipv6Mode
import com.dpsmpx.dppass.tunnel.TunnelOwner
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.job
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger

/**
 * Сервис туннеля в процессе приложения (D-17, D-30): foreground с типом
 * `specialUse`, TUN по `TunnelSpec`, ядро Xray на его fd.
 *
 * Запуск: активная конфигурация → `AndroidTunnelProvider.establish` →
 * `toTunInput()` → `DPpassCore.connect`. Кандидаты перебираются по плану
 * (D-15), сервер, выбранный пользователем, — первым (D-34); каждый
 * проверяется по полезной нагрузке — запросом DNS через сервер профиля к
 * DNS-серверу конфигурации (D-32). Ни один не прошёл — TUN закрывается и
 * сервис останавливается с причиной: TUN без ядра «съел» бы весь трафик
 * устройства.
 *
 * Жизненный цикл (D-40): пока туннель нужен — `START_STICKY`, и после
 * гибели процесса система запускает сервис заново без интента; always-on
 * VPN запускает его действием `android.net.VpnService`. В обоих случаях
 * поднимается последняя активная конфигурация (D-07). Остановка
 * пользователем — `START_NOT_STICKY`.
 *
 * Пока туннель поднят: сеть под ним — `setUnderlyingNetworks` по сети без
 * VPN, выбранной [NetworkCheck.underlying] (система и приложения видят её
 * тип и тарификацию); счётчики
 * ядра раз в секунду → [TunnelState.traffic], уведомление — реже и только
 * при включённом экране ([NotificationPace]).
 *
 * Раздача другим устройствам (D-51), если пользователь её включил: входы
 * ядра на адресах интерфейсов раздачи ([TetherInterfaces]); пока туннель
 * поднят, набор интерфейсов опрашивается, и при смене туннель
 * переподключается с новыми входами.
 *
 * Остановка — сначала ядро, потом fd TUN (fd принадлежит платформе, D-25):
 * действием [ACTION_STOP], при `onRevoke` (пользователь отозвал VPN или
 * включил другой) и в `onDestroy`. [ACTION_RECONNECT] — остановка и новый
 * запуск: другой выбранный сервер, новая конфигурация.
 *
 * Сбой выбранного сервера (D-58): ответы на вопрос [ServerSwitch] —
 * [ACTION_SWITCH] (замена становится выбранной, переподключение) и
 * [ACTION_KEEP] («Остаться»: не спрашивать о нём до остановки туннеля).
 *
 * Смена сети под туннелем (D-67): режим сети сессии берётся заново, а через
 * паузу новая сеть проверяется — если пользователь не выключил это в
 * настройках ([AppPrefs.checkOnNetworkChange]).
 */
class DPpassVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Состояние туннеля меняется только под этим замком: запуск и остановка не пересекаются. */
    private val state = Mutex()

    /**
     * Остановка и запуск — по очереди, целиком: следующее переподключение
     * начинается, когда прежнее закончилось. Журнал 19.10.2026: пользователь
     * выбирал серверы один за другим, новое подключение начиналось, пока
     * прежнее ещё стояло в пробе здоровья, — и все его попытки получили
     * «ядро уже запущено». Порядок замков: этот — снаружи, [state] — внутри.
     */
    private val lifecycle = Mutex()

    /**
     * Переподключения в очереди [lifecycle]: пока ждут, новых выборов может
     * прийти несколько — подключается только последний, промежуточные лишь
     * останавливают прежнее.
     */
    private val restarts = AtomicInteger()

    private var connecting: Job? = null
    private var session: EngineSession? = null
    private var rootZapret2: RootDpiRuntime? = null
    private var byeDpi: ByeDpiRuntime? = null
    private var byeDpiWatch: Job? = null
    private var rootWatch: Job? = null
    /** Alpine's sole strategy planner for local VpnService mode. */
    private var alpineStrategy: AlpineZapret2Runtime? = null
    private var alpineWatch: Job? = null
    private val tunnel = TunnelOwner()
    private var ticker: Job? = null
    // Keep a short-session diagnostic baseline outside the 30-second ticker.
    // Shutdown records it before stopping Xray; no destination information.
    private data class Zapret2FinalState(
        val session: EngineSession,
        val counters: Zapret2FinalCounter,
        val startedMillis: Long,
        val initialStages: Zapret2Stages?,
    )
    @Volatile private var zapret2FinalState: Zapret2FinalState? = null
    private var supervisor: Job? = null
    private var shareWatch: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** Пауза после смены сети и проверка новой (D-67); новая смена отменяет прежнюю. */
    @Volatile
    private var changeCheck: Job? = null

    /**
     * Смены сети (D-67) — на всё время работы сервиса, а не одной сессии:
     * переподключение посреди паузы после смены (наблюдатель, раздача) не
     * отменяет проверку новой сети и не делает её «сетью подключения».
     * Сервис уходит — уходит и ожидающая проверка (`scope.cancel`).
     */
    private var changes: NetworkChangeChecks? = null

    /** Тип последней сети под туннелем — для `network_changed from=…` и после переподключения. */
    @Volatile
    private var underlyingType = NetworkType.NONE

    /**
     * Режим сети сессии (D-64): берётся при подключении и заново — при смене
     * сети и после проверки новой (D-67). Пишут колбэк сети и проверка,
     * читает наблюдатель сессии.
     */
    @Volatile
    private var sessionRegime: NetworkAssessment? = null

    /**
     * Сервер, который держит сессия при выключенном автопереключении (D-113),
     * если пользователь не выбрал свой: тот, к которому подключились. Сбрасывается
     * выбором пользователя и остановкой сервиса.
     */
    @Volatile
    private var pinned: ProfileId? = null

    /** Подключение через устройство раздачи (D-55): сеть под ним — своя, «сеть пропала» к нему не относится. */
    @Volatile
    private var viaRelay = false

    /** Восстановление после пропажи сети или отказа (D-113): ждёт сеть, переподключает тем же сервером. */
    @Volatile
    private var recovery: Job? = null

    /** Серверы, о которых пользователь ответил «Остаться» (D-58): до остановки туннеля, то есть этого сервиса. */
    private val declined: MutableSet<ProfileId> = Collections.synchronizedSet(HashSet())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_SWITCH -> {
                ServerSwitch.clear(this)
                // Выбор пользователя — новый сервер: прежнее восстановление и закрепление ни к чему (D-113).
                cancelRecovery()
                pinned = null
                val to = intent.getStringExtra(EXTRA_PROFILE)?.takeIf(Ids::isValid)?.let(::ProfileId)
                if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
                restarts.incrementAndGet()
                scope.launch {
                    val core = AppGraph.core(this@DPpassVpnService)
                    if (core.activation.state.activeConfig == null) core.restoreAwaitingActivation()
                    // Конфигурация могла смениться, пока вопрос висел: замена — только из действующей,
                    // иначе — переподключение с прежним выбором (пользователь просил рабочее соединение).
                    if (to != null && core.activation.state.activeConfig?.profiles?.any { it.id == to } == true) {
                        AppPrefs(this@DPpassVpnService).selectedServer = to
                        core.log.info("server_switched", "to" to Safe(to.value), "by" to Safe("user"))
                    } else {
                        core.log.info("server_switch_stale")
                    }
                    restart()
                }
                return START_STICKY
            }
            ACTION_KEEP -> {
                ServerSwitch.clear(this)
                intent.getStringExtra(EXTRA_PROFILE)?.takeIf(Ids::isValid)?.let { id ->
                    declined += ProfileId(id)
                    DeviceLog.log.info("server_switch_declined", "profile" to Safe(id))
                }
                if (TunnelState.status.value.busy) return START_STICKY
                // Ответ пришёл, когда туннеля уже нет: сервису нечего делать.
                stopSelf()
                return START_NOT_STICKY
            }
            ACTION_STOP -> {
                DeviceLog.log.info("service_stop_requested")
                cancelRecovery()
                TunnelState.set(TunnelStatus.Stopping)
                announce()
                scope.launch {
                    lifecycle.withLock { shutdown() }
                    TunnelState.set(TunnelStatus.Idle)
                    announce()
                    stopSelf()
                }
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                // Переподключение по выбору пользователя (сервер, «Автоматически») — прежнее закрепление не действует (D-113).
                val byUser = intent.getBooleanExtra(EXTRA_BY_USER, false)
                if (byUser) {
                    cancelRecovery()
                    pinned = null
                }
                DeviceLog.log.info("service_reconnect", "by" to Safe(if (byUser) "user" else "service"))
                if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
                restarts.incrementAndGet()
                scope.launch { restart() }
                return START_STICKY
            }
        }
        // Свой запуск, always-on (действие VpnService) или перезапуск после гибели процесса (интента нет).
        DeviceLog.log.info("service_start", "by" to Safe(if (intent == null) "restart" else intent.action ?: "app"))
        if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
        scope.launch { lifecycle.withLock { start() } }
        return START_STICKY
    }

    /** Остановить прежнее и подключиться заново — если за этим запросом не ждёт ещё один. */
    private suspend fun restart() {
        lifecycle.withLock {
            // Switching from VpnService to root must release the old TUN;
            // otherwise packets stay trapped in an inactive Android VPN.
            shutdown(keepTunnel = !AppPrefs(this@DPpassVpnService).zapret2Backend.rooted)
            if (restarts.decrementAndGet() == 0) start() else DeviceLog.log.info("service_reconnect_superseded")
        }
    }

    private suspend fun start() {
        state.withLock {
            if (connecting?.isActive == true || session != null || rootZapret2 != null) {
                DeviceLog.log.info("service_already_running")
                return
            }
            TunnelState.set(TunnelStatus.Connecting(null))
            announce()
            connecting = scope.launch { connectOrFail() }
        }
    }

    /**
     * Неожиданная ошибка внутри подключения — отказ с причиной (D-22), а не
     * «Подключение…» навсегда: у корутины на SupervisorJob исключение гасло
     * молча, и экран ждал (путь подключения на API 26, 31.10.2026). Отмена —
     * не отказ; нехватка памяти и прочие сбои машины — дальше, как были.
     */
    private suspend fun connectOrFail() {
        try {
            connect()
        } catch (e: CancellationException) {
            throw e
        } catch (e: VirtualMachineError) {
            throw e
        } catch (e: Throwable) {
            fail(Diagnostic.fromThrowable(DiagCode.INTERNAL_ERROR, "подключение прервала неожиданная ошибка", e))
        }
    }

    private suspend fun connect() {
        val graph = AppGraph.graph(this)
        val core = graph.core
        if (core.activation.state.activeConfig == null) core.restoreAwaitingActivation()
        // Zapret2 не использует профили Xray или внешние серверы; никогда не
        // подменяем обычную подписку без явного выбора в настройках.
        when (AppPrefs(this).zapret2Backend) {
            Zapret2Backend.OFF -> Unit
            Zapret2Backend.ROOT, Zapret2Backend.BYEDPI_ROOT -> {
                connectRootZapret2(core, AppPrefs(this).zapret2Backend.byedpi)
                return
            }
            Zapret2Backend.VPN_SERVICE, Zapret2Backend.BYEDPI_VPN -> {
                // Отдельный локальный TUN: Xray выполняет только перенос пакетов,
                // DPI-приём делает собственный Go dialer, без внешнего сервера.
                val p = AppPrefs(this)
                val hosts = Zapret2Hostlist.parse(p.zapret2HostlistText)
                if (hosts.isFailure) {
                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                        "Zapret2: некорректный список доменов: " + hosts.exceptionOrNull()?.message))
                    return
                }
                val list = hosts.getOrThrow()
                val sites = if (list.isEmpty) SplitSites.NONE else when (val parsed = SplitSites.parse(list.format())) {
                    is Outcome.Success -> parsed.value
                    is Outcome.Failure -> {
                        fail(parsed.errors.first())
                        return
                    }
                }
                // A nonempty allowlist limits desync to matching sites.
                // Without a list the local TCP/UDP trick applies to all destinations.
                val settings = p.serverless.copy(
                    rest = if (sites.isEmpty) ServerlessSettings.Rest.SPLIT else ServerlessSettings.Rest.DIRECT,
                    apps = ServerlessSettings.Apps.ALL,
                )
                // One user-facing mode. Old manually persisted modes are
                // ignored to avoid silently retaining an outdated fixed
                // strategy after updating from an earlier debug build.
                // Other candidates remain available to private diagnostics.
                val useByeDpi = p.zapret2Backend == Zapret2Backend.BYEDPI_VPN
                val trick = if (useByeDpi) null else DesyncTrick.Auto
                connectServerless(graph, sites, settings, trick,
                    if (useByeDpi) "ByeDPI VPN local" else "Zapret2 VPN local",
                    !useByeDpi && p.zapret2VpnForceTcp, !useByeDpi && p.zapret2VpnCatchAllHttps,
                    useByeDpi = useByeDpi)
                return
            }
        }
        // Устройство раздачи (D-55): выбрано — подключение только через него, по сети, где оно ответило.
        val relay = AppPrefs(this).selectedRelay?.let(core.relays::find)
        viaRelay = relay != null
        val target = relay?.let { d ->
            when (val t = withContext(Dispatchers.IO) { RelayNetworks.locate(this@DPpassVpnService, d) }) {
                is Outcome.Failure -> {
                    fail(t.errors.first())
                    return
                }
                is Outcome.Success -> t.value.also { core.log.info("relay_found", "medium" to Safe(it.medium.name), "auto" to (d.address == null)) }
            }
        }
        // Без VPN (D-95): локальный прокси вместо TUN; порт занят — новый, свободного нет — отказ до серверов.
        val local = when (val l = withContext(Dispatchers.IO) { core.localProxy.prepare() }) {
            is Outcome.Failure -> {
                fail(l.errors.first())
                return
            }
            is Outcome.Success -> l.value.also { l.diagnostics.forEach(core.log::diagnostic) }
        }
        // Без сервера (D-73): серверов нет, устройство раздачи не выбрано, а сайтам списка нужен туннель.
        val prefs = AppPrefs(this)
        val sites = prefs.splitSites()
        val serverless = prefs.serverless
        if (core.serverlessReady(sites, serverless, relaySelected = relay != null)) {
            if (local != null) {
                val why = "серверов нет, а режим без сервера (D-73) работает только через VPN — без VPN подключаться не к чему"
                fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, why))
                return
            }
            connectServerless(graph, sites, serverless)
            return
        }
        val ir = if (relay != null && target != null) core.relayConfig(relay, target.address) else core.activation.state.activeConfig
        if (ir == null) {
            fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — туннель не поднимается"))
            return
        }
        // Через VPN — TUN по политике приложений; без VPN (D-95) TUN нет, и выбор приложений не действует.
        val tunSpec = if (local != null) {
            null
        } else {
            when (val spec = core.tunnelSpecFor(ir)) {
                is Outcome.Failure -> {
                    fail(spec.errors.first())
                    return
                }
                is Outcome.Success -> spec.value
            }
        }
        val handle = tunSpec?.let { spec ->
            when (val t = AndroidTunnelProvider(this).establish(spec)) {
                is Outcome.Failure -> {
                    t.errors.drop(1).forEach(core.log::diagnostic)
                    fail(t.errors.first())
                    return
                }
                is Outcome.Success -> t.value
            }
        }
        tunnel.replace(handle)
        if (tunSpec != null) {
            core.log.info("tunnel_up", "routes" to tunSpec.routes.size, "apps" to Safe(tunSpec.apps::class.simpleName ?: "?"))
        } else {
            core.log.info("local_proxy_up", "port" to local?.port)
        }
        // Проба здоровья (D-32) блокирует поток — не дольше своего срока, меньше срока плана.
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, profile ->
            progress(TunnelStatus.Connecting(profile.name))
            withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, probeTimeout) }
        }
        // Автопереключение выключено (D-113): сервер, который сессия держит, не меняется сам — только он и пробуется.
        val strictId = if (relay == null) pinTarget(core) else null
        val preferred = strictId ?: AppPrefs(this).selectedServer
        // Only the actual "Automatically" server selection may use the
        // optional model; explicit pins/relays are never overridden.
        val autoProviderModel = relay == null && preferred == null
        val networkForServerAuto = NetworkCheck.underlying(this).type
        if (strictId != null) core.log.info("server_pinned", "profile" to Safe(strictId.value))
        // Белый список по свежей проверке в этой сети (D-64): порядок плана и опыт попыток — его.
        // Через устройство раздачи (D-55) путь идёт по своей сети — режим оператора ни при чём.
        val regime = if (relay == null) NetworkCheck.regime(this) else null
        regime?.let { core.log.info("network_regime", "class" to it.restriction, "age_s" to (NetworkCheck.regimeAgeMillis() ?: 0) / 1000) }
        val failingUnderRegime = regime?.let(core::failingUnder).orEmpty()
        // Раздача (D-51): входы — на адресах интерфейсов раздачи, если пользователь её включил.
        val shareSettings = core.share.current().also { r -> r.diagnostics.forEach(core.log::diagnostic) }.valueOrNull()
        val share = if (shareSettings?.enabled == true) shareSettings.spec(tetherForConnect()) else null
        val job = currentCoroutineContext().job
        val report = try {
            val tun = handle?.toTunInput()?.let { base ->
                // Сокеты ядра — в сеть устройства раздачи: с Bluetooth- и USB-модема путь к нему не по умолчанию.
                if (target == null) {
                    base
                } else {
                    base.copy(protector = SocketProtector { fd -> base.protector.protect(fd) && RelayNetworks.bind(target.network, fd) })
                }
            }
            if (relay != null && target != null) {
                core.connectVia(relay, target.address, checker, tun, share, local) { delay(it) }
            } else {
                // Разбиение ClientHello к серверу (D-68) — выбор пользователя; к устройству раздачи — нет.
                val split = prefs.splitClientHello
                core.log.info("client_hello_split", "on" to split)
                // Сайты напрямую с разбиением (D-72): в журнал — число записей, не сами сайты.
                core.log.info("split_sites", "n" to sites.size)
                core.connect(null, checker, tun, preferred, share, regime, split, sites, local,
                    pinned = strictId != null,
                    rerank = if (autoProviderModel) ({ plan ->
                        ServerAutoModel.rerank(this, plan, core, networkForServerAuto, core.clock.nowMillis())
                    }) else null
                ) { delay(it) }
            }
        } catch (e: CancellationException) {
            // Остановка во время подключения: сеанс, запущенный посреди проверки
            // здоровья, оркестратор уже остановил (ConnectionOrchestrator.tryOne);
            // остаётся TUN.
            throw e
        }
        // План и исходы попыток — для «Почему этот сервер» (D-15), и при отказе тоже.
        report?.let {
            TunnelState.plan(PlanSnapshot(core.clock.nowMillis(), it.attempts, it.plan.excluded, viaRelay = relay != null))
            if (autoProviderModel) ServerAutoModel.observe(this, it, core)
        }
        when (report) {
            is ConnectionReport.Connected -> withContext(NonCancellable) {
                // Вызовы ядра не прерываются отменой: остановка могла прийти, пока
                // шёл запуск. Тогда сеанс не принимается, а сразу останавливается.
                val accepted = state.withLock {
                    if (job.isCancelled) {
                        false
                    } else {
                        session = report.session
                        true
                    }
                }
                if (accepted) {
                    core.log.info("connected", "profile" to Safe(report.profileId.value), "attempts" to report.attempts.size)
                    // Автопереключение выключено: держим именно этот сервер, пока пользователь не выберет другой (D-113).
                    // With the separately generated server AUTO model, choosing
                    // "Automatically" explicitly allows a fresh comparison at
                    // the next connection. An explicitly selected server is
                    // still pinned and never replaced by ML.
                    if (relay == null && !AppPrefs(this@DPpassVpnService).autoSwitch &&
                        (AppPrefs(this@DPpassVpnService).selectedServer != null ||
                         !Zapret2NeuralModel.isInstalled(this@DPpassVpnService, Zapret2NeuralModel.Kind.SERVER))) {
                        pinned = report.profileId
                    } else {
                        pinned = null
                    }
                    // Подключился сервер, который под белым списком только отказывал: список, скорее всего,
                    // выключили — режим снова неизвестен, порядок и опыт — общие (D-64).
                    val contradicted = regime != null && report.profileId in failingUnderRegime
                    if (contradicted) {
                        NetworkCheck.forgetRegime()
                        core.log.info("network_regime_dropped", "reason" to Safe("contradicted"), "profile" to Safe(report.profileId.value))
                    }
                    // Вопрос был о другом сервере (пользователь выбрал сам, подключение через устройство) — снят.
                    TunnelState.offer.value?.takeIf { it.fromId != report.profileId }?.let { ServerSwitch.clear(this@DPpassVpnService) }
                    val name = ir.profiles.firstOrNull { it.id == report.profileId }?.name ?: report.profileId.value
                    // Без VPN (D-95): адрес прокси — на экране подключения и в уведомлении.
                    TunnelState.localProxy(local)
                    progress(TunnelStatus.Connected(report.profileId, name, core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
                    // Режим сессии — до того, как колбэк сети может взять его заново (D-67).
                    sessionRegime = if (contradicted) null else regime
                    watchNetwork(target?.network)
                    startTicker(report.session)
                    // IPv6 через сервер (D-66): только когда TUN его берёт и путь — свой сервер, а не устройство раздачи.
                    val checkIpv6 = relay == null && tunSpec?.ipv6Mode == Ipv6Mode.TUNNELED
                    startSupervisor(core, graph.engine, ir, report.profileId, checkIpv6)
                    if (shareSettings?.enabled == true) {
                        // Ядро с входами раздачи не запустилось — туннель без неё (D-51).
                        // Опрос сравнивает с предложенными адресами: тот же набор — без
                        // переподключения по кругу; набор сменился — новая попытка.
                        val offered = share?.endpoints.orEmpty()
                        val refused = report.shareRefused != null
                        TunnelState.share(if (refused) emptyList() else offered, refused)
                        core.log.info("share", "endpoints" to offered.size, "refused" to refused)
                        startShareWatch(core, offered)
                    }
                } else {
                    report.session.stop()
                }
            }
            is ConnectionReport.Failed -> {
                fail(report.reason)
                // TUN остаётся (D-111) — VPN не отключаем: ждём сеть и пробуем снова тем же сервером (D-113).
                if (tunnel.present && relay == null) startRecovery(core, report.reason)
            }
            null -> {
                fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — подключаться не к чему"))
            }
        }
    }

    /**
     * Без сервера (D-73): TUN по выбору приложений режима, ядро только с
     * прямыми выходами, проба DoH напрямую. Наблюдатель сессии (D-44),
     * вопрос о смене сервера (D-58) и проба IPv6 через сервер (D-66) не
     * запускаются: сервера нет.
     */
    /** Root NFQUEUE, только отдельный экспериментальный режим. */
    private suspend fun connectRootZapret2(core: DPpassCore, useByeDpi: Boolean) {
        val name = if (useByeDpi) "ByeDPI root" else "Zapret2 root"
        progress(TunnelStatus.Connecting(name))
        val root: RootDpiRuntime = if (useByeDpi) RootByeDpi(this) else RootZapret2(this)
        // Root-команда завершается или откатывается, даже если пользователь нажал «Стоп».
        val result = withContext(NonCancellable) { root.start() }
        if (result.isFailure) {
            fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                name + ": " + (result.exceptionOrNull()?.message?.let { message ->
                    if (message.contains("Permission denied") && message.contains("su"))
                        "root-доступ недоступен: Android отказал в запуске su" else message
                } ?: "движок недоступен")))
            return
        }
        val job = currentCoroutineContext().job
        val accepted = state.withLock {
            if (job.isCancelled) false else {
                rootZapret2 = root
                true
            }
        }
        if (!accepted) {
            root.stop()
            return
        }
        progress(TunnelStatus.Connected(ProfileId(if (useByeDpi) "byedpi-root" else "zapret2-root"), name,
            core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
        rootWatch = scope.launch {
            while (isActive) {
                delay(5_000L)
                if (!root.alive()) {
                    root.stop().onFailure { error ->
                        DeviceLog.log.diagnostic(Diagnostic.fromThrowable(
                            DiagCode.BACKEND_NOT_AVAILABLE, "не удалось снять правила Zapret2 после сбоя", error,
                        ))
                    }
                    rootZapret2 = null
                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, name + ": процесс больше не работает"))
                    break
                }
            }
        }
    }

    private suspend fun connectServerless(
        graph: AppGraph.Graph,
        sites: SplitSites,
        settings: ServerlessSettings,
        desync: DesyncTrick? = null,
        label: String? = null,
        forceQuicTcp: Boolean = false,
        catchAllHttps: Boolean = false,
        useByeDpi: Boolean = false,
    ) {
        val core = graph.core
        val name = label ?: getString(R.string.serverless_name)
        // RC3 field evidence: the local mobile adapter repeatedly dials
        // unreachable IPv6 peers while IPv4 controls work. Do not advertise
        // AAAA to applications in this experimental mobile mode. Keep IPv6
        // TUN routes to avoid silently bypassing the VPN.
        val localEngine = desync != null || useByeDpi
        val ipv4Only = localEngine && NetworkCheck.underlying(this).type == NetworkType.MOBILE
        val tunSpec = when (val spec = core.tunnelSpecFor(core.serverlessConfig(settings, ipv4Only))) {
            is Outcome.Failure -> {
                fail(spec.errors.first())
                return
            }
            is Outcome.Success -> spec.value
        }
        val handle = when (val t = AndroidTunnelProvider(this).establish(tunSpec)) {
            is Outcome.Failure -> {
                t.errors.drop(1).forEach(core.log::diagnostic)
                fail(t.errors.first())
                return
            }
            is Outcome.Success -> t.value
        }
        tunnel.replace(handle)
        if (useByeDpi) {
            val started = withContext(NonCancellable + Dispatchers.IO) {
                runCatching { ByeDpiRuntime.start(this@DPpassVpnService) }.also { result ->
                    byeDpi = result.getOrNull()
                }
            }
            if (started.isFailure) {
                fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                    "ByeDPI: " + (started.exceptionOrNull()?.message ?: "startup failed")))
                return
            }
        }
        // Only create a PRoot process after Android has granted VPN consent
        // and established its TUN. Otherwise a rejected permission request
        // starts a daemon that must immediately be destroyed.
        // Android retains TUN/protected sockets; the Alpine-enabled APK
        // must select its bundled planner or fail, never silently switch to
        // an in-process decision maker when PRoot binaries are unavailable.
        if (desync != null && AppPrefs(this).zapret2Backend == Zapret2Backend.VPN_SERVICE) {
            val bundled = AlpineFiles.bundled(this)
            val selection = AlpinePlannerSelection.choose(
                bundled = bundled,
                supported = bundled && AlpineFiles.supported(this),
            )
            when (selection) {
                AlpinePlannerSelection.IN_PROCESS -> {
                    // Standard APK only. Same shared algorithm, without PRoot.
                    core.log.info("zapret2_planner", "mode" to Safe("in_process"),
                        "reason" to Safe("alpine_not_packaged"))
                }
                AlpinePlannerSelection.UNAVAILABLE -> {
                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                        "Zapret2 Alpine включён в APK, но PRoot или его загрузчик недоступен"))
                    return
                }
                AlpinePlannerSelection.ALPINE -> {
                    core.log.info("zapret2_alpine_start", "status" to Safe("initializing"))
                    val started = runCatching { AlpineZapret2Runtime.start(this) }
                    val daemon = started.getOrNull()
                    if (daemon == null) {
                        fail(Diagnostic.fromThrowable(DiagCode.BACKEND_NOT_AVAILABLE,
                            "Zapret2 Alpine: стратегия не запустилась", started.exceptionOrNull()!!))
                        return
                    }
                    alpineStrategy = daemon
                    core.log.info("zapret2_alpine_ready", "status" to Safe("socket_probed"),
                        "process_alive" to daemon.isAlive)
                    when (val selected = JniXrayRuntime.configureZapret2Planner(daemon.socketPath)) {
                        is XrayResult.Failed -> {
                            daemon.close()
                            alpineStrategy = null
                            fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                                "Не удалось включить Alpine-движок Zapret2: " + selected.text.take(200)))
                            return
                        }
                        else -> Unit
                    }
                    core.log.info("zapret2_planner", "mode" to Safe("alpine"),
                        "status" to Safe("selected"))
                }
            }
        }
        if (desync != null && AppPrefs(this).zapret2Backend == Zapret2Backend.VPN_SERVICE) {
            // Go stores only user-selected destinations, not traffic logs;
            // changing the selection never interrupts an existing TLS flow.
            val targets = AppPrefs(this).zapret2AdaptiveTargetsText
            when (val chosen = JniXrayRuntime.configureZapret2AdaptiveHosts(targets)) {
                is XrayResult.Failed -> {
                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                        "Некорректный список адресов автоподбора Zapret2: " + chosen.text.take(160)))
                    return
                }
                else -> {
                    val automaticTcp = desync == DesyncTrick.Auto
                    core.log.info("zapret2_adaptive_enabled",
                        "all_tcp" to automaticTcp,
                        "selected" to targets.lines().count { it.isNotBlank() },
                        "quic_trials_enabled" to (automaticTcp && !forceQuicTcp))
                    // AUTO means adaptive *TCP*. A previously saved QUIC→TCP
                    // preference may still block all QUIC Initials. Do not
                    // override the user's switch: report the effective scope.
                    if (automaticTcp && forceQuicTcp) {
                        core.log.warning("zapret2_auto_quic_blocked",
                            "reason" to Safe("force_tcp_enabled"))
                    }
                }
            }
            // Locally generated MLP is optional. Reuse learned scenario
            // weights from private storage rather than a downloaded seed.
            val networkClass = when (NetworkCheck.underlying(this).type) {
                NetworkType.MOBILE -> "MOBILE"
                NetworkType.WIFI -> "WIFI"
                else -> "OTHER"
            }
            JniXrayRuntime.configureZapret2NeuralNetwork(networkClass)
            val modelBytes = Zapret2NeuralModel.readVerified(this)
            when (val configured = JniXrayRuntime.configureZapret2NeuralModel(modelBytes ?: ByteArray(0))) {
                is XrayResult.Failed -> core.log.warning("zapret2_neural_model_rejected",
                    "reason" to Safe("invalid_model"))
                else -> core.log.info("zapret2_neural_model",
                    "installed" to (modelBytes != null), "mode" to Safe("local_only"))
            }
        }
        core.log.info("tunnel_up", "routes" to tunSpec.routes.size, "apps" to Safe(tunSpec.apps::class.simpleName ?: "?"))
        progress(TunnelStatus.Connecting(name))
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val job = currentCoroutineContext().job
        val result = try {
            core.connectServerless(handle.toTunInput(), sites, settings,
                desync = desync, forceQuicTcp = forceQuicTcp, catchAllHttps = catchAllHttps,
                byeDpiPort = byeDpi?.port, byeDpiToken = byeDpi?.token, ipv4Only = ipv4Only) { _, dns ->
                withContext(Dispatchers.IO) {
                    val health = graph.engine.probeServerless(dns, probeTimeout)
                    if (health is Outcome.Success && localEngine) {
                        // One bounded, public Google control, using the virtual DNS
                        // route and regular dispatcher. No user URLs or IPs logged.
                        runCatching { JniXrayRuntime.localRouteControl(6_000) }
                            .onSuccess { r ->
                                core.log.info("local_route_control",
                                    "scope" to Safe("dispatcher_not_android_tun"),
                                    "outcome" to r.outcome,
                                    "stage" to Safe(if (r.outcome == com.dpsmpx.dppass.engine.xray.DnsProbeOutcome.OK) "http_200" else
                                        r.text.takeIf { it.matches(Regex("[a-z_]{1,40}")) } ?: "unknown"),
                                    "ms" to r.elapsedMillis, "body_bytes" to r.receivedBytes)
                            }
                    }
                    health
                }
            }
        } catch (e: CancellationException) {
            throw e
        }
        when (result) {
            is Outcome.Failure -> {
                fail(result.errors.first())
            }
            is Outcome.Success -> withContext(NonCancellable) {
                val session = result.value
                val accepted = state.withLock {
                    if (job.isCancelled) {
                        false
                    } else {
                        this@DPpassVpnService.session = session
                        true
                    }
                }
                if (accepted) {
                    core.log.info("connected", "profile" to Safe(ServerlessPlan.PROFILE_ID.value),
                        "attempts" to 1, "local_desync" to (desync != null),
                        "local_backend" to Safe(if (useByeDpi) "byedpi" else if (desync != null) "zapret2" else "serverless"),
                        "content_verified" to false,
                        "zapret2_planner" to Safe(if (desync == null) "off" else if (alpineStrategy != null) "alpine" else "in_process"))
                    progress(TunnelStatus.Connected(ServerlessPlan.PROFILE_ID, name, core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
                    watchNetwork()
                    startTicker(session)
                    byeDpi?.let { daemon ->
                        byeDpiWatch?.cancel()
                        byeDpiWatch = scope.launch {
                            while (isActive) {
                                delay(2_000L)
                                if (!daemon.isAlive) {
                                    session.stop()
                                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE, "ByeDPI process stopped"))
                                    break
                                }
                            }
                        }
                    }
                    alpineStrategy?.let { daemon ->
                        alpineWatch?.cancel()
                        alpineWatch = scope.launch {
                            while (isActive) {
                                delay(5_000L)
                                if (!daemon.isAlive) {
                                    fail(Diagnostic.error(DiagCode.BACKEND_NOT_AVAILABLE,
                                        "Запущенный движок Zapret2 в Alpine завершился; трафик не обходится напрямую"))
                                    break
                                }
                            }
                        }
                    }
                } else {
                    session.stop()
                }
            }
        }
    }

    /**
     * Счётчики ядра → скорость и итоги (D-40). Раз в секунду, пока экран
     * включён; уведомление — реже: каждое обновление стоит батареи.
     */
    // Aggregate counters only. They do not identify an app or certify
    // DNS, TLS handshake completion, HTTP response, or media playback.
    private fun logZapret2Stages(event: String, s: Zapret2Stages) {
        AppGraph.core(this).log.info(event,
            "scope" to Safe("experimental_outbounds"),
            "tcp_dial_ok" to s.tcpDialOk,
            "tcp_dial_timeout" to s.tcpDialTimeout,
            "tcp_dial_refused" to s.tcpDialRefused,
            "tcp_dial_unreachable" to s.tcpDialUnreachable,
            "tcp_dial_other" to s.tcpDialOther,
            "tcp_dial_ok_ipv4" to s.tcpDialOkV4,
            "tcp_dial_ok_ipv6" to s.tcpDialOkV6,
            "tcp_dial_ok_unknown" to s.tcpDialOkUnknown,
            "tcp_unreachable_ipv4" to s.tcpDialUnreachableV4,
            "tcp_unreachable_ipv6" to s.tcpDialUnreachableV6,
            "tcp_unreachable_unknown" to s.tcpDialUnreachableUnknown,
            "tcp_clienthello_sent" to s.tcpHelloSent,
            "tcp_clienthello_failed" to s.tcpHelloFailed,
            "tcp_first_reply" to s.tcpFirstReply,
            "tcp_closed_no_reply" to s.tcpClosedNoReply,
            "tcp_tls_alert" to s.tcpFirstTlsAlert,
            "tcp_read_timeout" to s.tcpReadTimeout,
            "quic_initial_sent" to s.udpInitialSent,
            "quic_initial_failed" to s.udpInitialFailed,
            "udp_first_reply" to s.udpFirstReply,
            "udp_closed_no_reply" to s.udpClosedNoReply)
    }

    private fun startTicker(session: EngineSession) {
        ticker?.cancel()
        val diagnosticEnabled = AppPrefs(this).zapret2Backend == Zapret2Backend.VPN_SERVICE
        val initialCounters = if (diagnosticEnabled) AppGraph.graph(this).engine.desyncCounters() else null
        val initialStages = if (diagnosticEnabled) AppGraph.graph(this).engine.zapret2Stages() else null
        val diagnostic = if (diagnosticEnabled) Zapret2FinalCounter(
            initialCounters?.applied ?: 0L, initialCounters?.skipped ?: 0L) else null
        zapret2FinalState = diagnostic?.let { Zapret2FinalState(session, it, Clock.MONOTONIC.nowMillis(), initialStages) }
        ticker = scope.launch {
            val meter = TrafficMeter(averageMillis = 5_000)
            var quality: LongArray? = null
            var qualityTick = 0
            val pace = NotificationPace()
            val power = getSystemService(PowerManager::class.java)
            val core = AppGraph.core(this@DPpassVpnService)
            // Учёт трафика (D-92) — и с выключенным экраном: приращения сеанса, сеть — та, что под туннелем.
            val usage = UsageMeter()
            val graph = AppGraph.graph(this@DPpassVpnService)
            val owners = graph.owners
            var diagUp = 0L
            var diagDown = 0L
            var localAllUp = 0L
            var localAllDown = 0L
            var localProxyUp = 0L
            var localProxyDown = 0L
            // Xray desync counters are process-wide; baselines must start at
            // this VPN session, unlike per-session traffic counters.
            var diagApplied = initialCounters?.applied ?: 0L
            var diagSkipped = initialCounters?.skipped ?: 0L
            var lastStages = initialStages
            var ticks = 0L
            while (isActive) {
                core.usage.record(usage.delta(session.stats()), underlyingType)?.let { UsageAlerts.show(this@DPpassVpnService, core, it) }
                // Журнал уникальных соединений (D-106) пополняется и с закрытым экраном: закрытые ядро держит
                // 5 минут, опроса раз в 10 с хватает. Без журнала опрашивать незачем — таблицу опрашивает её экран.
                if (ticks++ % ANALYZER_EVERY_TICKS == 0L && core.analyzer.settings().let { it.enabled && it.keepUnique }) core.analyzer.poll(owners)
                // A successful DoH probe cannot prove that YouTube feed/CDN
                // payloads arrived. Periodic privacy-safe transport counters
                // make "connected but feed stalls" measurable in device logs.
                if (ticks % 30L == 0L && AppPrefs(this@DPpassVpnService).zapret2Backend in
                    setOf(Zapret2Backend.VPN_SERVICE, Zapret2Backend.BYEDPI_VPN)) {
                    val proxyStats = session.stats()
                    val allStats = runCatching { JniXrayRuntime.displayTraffic() }.getOrNull()
                    if (allStats != null) {
                        val proxyUp = (proxyStats.uplinkBytes - localProxyUp).coerceAtLeast(0)
                        val proxyDown = (proxyStats.downlinkBytes - localProxyDown).coerceAtLeast(0)
                        val allUp = (allStats.uplinkBytes - localAllUp).coerceAtLeast(0)
                        val allDown = (allStats.downlinkBytes - localAllDown).coerceAtLeast(0)
                        core.log.info("local_path_window",
                            "backend" to Safe(if (byeDpi != null) "byedpi" else "zapret2"),
                            "proxy_up" to proxyUp, "proxy_down" to proxyDown,
                            "other_up" to (allUp - proxyUp).coerceAtLeast(0),
                            "other_down" to (allDown - proxyDown).coerceAtLeast(0))
                        localAllUp = allStats.uplinkBytes
                        localAllDown = allStats.downlinkBytes
                        localProxyUp = proxyStats.uplinkBytes
                        localProxyDown = proxyStats.downlinkBytes
                    }
                }
                if (ticks % 30L == 0L && AppPrefs(this@DPpassVpnService).zapret2Backend == Zapret2Backend.VPN_SERVICE) {
                    val stats = session.stats()
                    val probes = graph.engine.desyncCounters()
                    core.log.info("zapret2_transfer_window",
                        "up_bytes" to (stats.uplinkBytes - diagUp).coerceAtLeast(0),
                        "down_bytes" to (stats.downlinkBytes - diagDown).coerceAtLeast(0),
                        "applied_delta" to ((probes?.applied ?: diagApplied) - diagApplied).coerceAtLeast(0),
                        "skipped_delta" to ((probes?.skipped ?: diagSkipped) - diagSkipped).coerceAtLeast(0),
                        "applied_total" to (probes?.applied ?: 0L),
                        "skipped_total" to (probes?.skipped ?: 0L))
                    diagUp = stats.uplinkBytes
                    diagDown = stats.downlinkBytes
                    if (probes != null) {
                        diagApplied = probes.applied
                        diagSkipped = probes.skipped
                    }
                    val nowStages = graph.engine.zapret2Stages()
                    if (lastStages != null && nowStages != null) {
                        logZapret2Stages("zapret2_stage_window", nowStages.delta(lastStages))
                    }
                    lastStages = nowStages
                    // Export only modified bounded weights. No network request
                    // and no domain names are written to this private file.
                    withContext(Dispatchers.IO) { persistStrategyLearning() }
                }
                val interactive = power.isInteractive
                val notify = pace.tick(interactive)
                if (interactive) {
                    if (qualityTick++ % 2 == 0) {
                        // The loopback SOCKS hop is not internet RTT. Until original
                        // ciadpi exports its own TCP_INFO, show no misleading sample.
                        quality = if (byeDpi != null) null else runCatching { JniXrayRuntime.passiveQuality() }.getOrNull()
                    }
                    val displayStats = runCatching { JniXrayRuntime.displayTraffic() }.getOrNull() ?: session.stats()
                    val traffic = meter.sample(displayStats, Clock.MONOTONIC.nowMillis()).copy(
                        pingMicros = quality?.get(0), jitterMicros = quality?.get(1))
                    TunnelState.traffic(traffic)
                    if (notify) (TunnelState.status.value as? TunnelStatus.Connected)?.let { startInForeground(it, traffic) }
                } else {
                    // Экран выключен: никто не смотрит — отсчёт скорости заново после включения.
                    meter.reset()
                    quality = null
                    qualityTick = 0
                }
                delay(NotificationPace.TICK_MILLIS)
            }
        }
    }

    /**
     * Наблюдатель сессии (D-44): раз в [SUPERVISION_INTERVAL_MILLIS] проба
     * здоровья (D-32), наблюдение в адаптивную модель и, при подтверждённой
     * деградации (гистерезис, не один сбой — T14), переподключение. Модель
     * периодически сохраняется, чтобы опыт пережил перезапуск процесса.
     *
     * Переподключение идёт через [ACTION_RECONNECT] — проверенный путь
     * жизненного цикла. Сбоивший сервер к этому моменту получил отказ в
     * журнале здоровья (D-58), и план без выбора пользователя начнёт с
     * другого кандидата; выбранный пользователем заменяется только с его
     * согласия — вопросом [ServerSwitch] или тумблером «Автопереключение».
     *
     * Опыт сессии — в контексте её режима сети ([sessionRegime], D-64); сеть
     * сменилась — режим взят заново, и следующая проба идёт в новый (D-67).
     */
    private fun startSupervisor(
        core: com.dpsmpx.dppass.connection.DPpassCore,
        engine: com.dpsmpx.dppass.engine.xray.XrayProxyEngine,
        ir: com.dpsmpx.dppass.config.ConfigIr,
        profileId: com.dpsmpx.dppass.core.ProfileId,
        /** Проверить, выпускает ли сервер IPv6 (D-66): раз за сессию, после удачной пробы. */
        checkIpv6: Boolean,
    ) {
        supervisor?.cancel()
        TunnelState.ipv6(null)
        supervisor = scope.launch {
            var applied = sessionRegime
            val sup = core.supervisor(profileId, applied)
            val profile = ir.profiles.firstOrNull { it.id == profileId }
            val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
            var samples = 0
            var lastFailure: Diagnostic? = null
            var ipv6Tries = if (checkIpv6) IPV6_TRIES else 0
            while (isActive) {
                delay(SUPERVISION_INTERVAL_MILLIS)
                // Наша ли ещё сессия: остановка или переподключение могли её сменить.
                if (state.withLock { session } == null) return@launch
                // Идёт свой замер (D-60, D-61) или он только что кончился: проба мерила бы его, а не сервер.
                if (NetworkCheck.probesQuiet()) {
                    core.log.info("adaptive_probe_skipped", "profile" to Safe(profileId.value), "reason" to Safe("measurement"))
                    continue
                }
                // Сети нет (D-113): проба мерила бы её отсутствие, а не сервер. Туннель держим, сервер не трогаем;
                // сеть вернётся — колбэк сети запустит восстановление.
                if (!networkUp()) {
                    core.log.info("adaptive_probe_skipped", "profile" to Safe(profileId.value), "reason" to Safe("network_down"))
                    continue
                }
                val started = Clock.MONOTONIC.nowMillis()
                val result = withContext(Dispatchers.IO) { engine.probeHealth(ir.dns, probeTimeout) }
                val elapsed = (Clock.MONOTONIC.nowMillis() - started).coerceAtLeast(1)
                val failed = result is Outcome.Failure
                // Сеть пропала, пока шла проба: исход — не про сервер, в модель и в журнал здоровья не идёт (D-113).
                if (!networkUp()) {
                    core.log.info("adaptive_probe_discarded", "profile" to Safe(profileId.value), "ok" to !failed, "reason" to Safe("network_down"))
                    continue
                }
                // Замер начался, пока шла проба: её исход — не про сервер, в модель не идёт (T14).
                if (NetworkCheck.probesQuiet()) {
                    core.log.info("adaptive_probe_discarded", "profile" to Safe(profileId.value), "ok" to !failed, "elapsed_ms" to elapsed)
                    continue
                }
                val stalled = failed && result.errors.any { it.code == DiagCode.PAYLOAD_STALLED }
                val regime = sessionRegime
                if (regime !== applied) {
                    sup.changeContext(regime)
                    applied = regime
                }
                val decision = sup.onObservation(
                    StabilityObservation(success = !failed, rttMillis = elapsed, stalled = stalled, timestampMillis = core.clock.nowMillis()),
                    profile,
                    regime,
                )
                if (failed) {
                    val reason = result.errors.first()
                    lastFailure = reason
                    // Причина (D-22): «ни байта», «соединение есть, ответа нет» и отказ TLS — разные беды, по одному времени их не различить.
                    core.log.warning(
                        "adaptive_probe_failed",
                        *listOfNotNull(
                            "profile" to Safe(profileId.value),
                            "elapsed_ms" to elapsed,
                            "code" to Safe(reason.code.name),
                            "reason" to reason.message,
                            reason.causes.firstNotNullOfOrNull { it.error?.message }?.let { "error" to it },
                        ).toTypedArray(),
                    )
                }
                if (++samples % PERSIST_EVERY_SAMPLES == 0 || decision == SessionSupervisor.Decision.RECONNECT) {
                    withContext(NonCancellable) { core.persistStability() }
                }
                if (decision == SessionSupervisor.Decision.RECONNECT) {
                    core.log.warning("adaptive_reconnect", "profile" to Safe(profileId.value))
                    // Деградация подтверждена и скачком задержки, без проваленной пробы — общая причина.
                    val reason = lastFailure ?: Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "пробы через сервер раз за разом отвечают с перебоями")
                    onDegraded(core, profileId, reason, regime)
                    reconnect(this@DPpassVpnService)
                    return@launch
                }
                // Выпускает ли сервер IPv6 (D-66): после удачной пробы — сервер сейчас работает.
                // Итог «не понять» — ещё попытка в следующий раз; замер начался — тоже.
                if (!failed && ipv6Tries > 0) {
                    val check = withContext(Dispatchers.IO) { engine.probeIpv6() }
                    if (NetworkCheck.probesQuiet()) continue
                    ipv6Tries = if (check.egress == Ipv6Egress.UNKNOWN) ipv6Tries - 1 else 0
                    core.log.info(
                        "ipv6_egress",
                        "profile" to Safe(profileId.value),
                        "result" to check.egress,
                        "outcomes" to Safe(check.outcomes.joinToString(",") { it.name }),
                        // Время каждой пробы: сервер отказывает по IPv6 сразу или ждёт своего срока.
                        "elapsed_ms" to Safe(check.results.joinToString(",") { it.elapsedMillis.toString() }),
                    )
                    if (check.egress != Ipv6Egress.UNKNOWN || ipv6Tries == 0) TunnelState.ipv6(Ipv6Note(profileId, check.egress, core.clock.nowMillis()))
                }
            }
        }
    }

    /**
     * Сбой сервера сессии (D-58): спросить о замене выбранного, заменить его
     * с согласием заранее или просто переподключиться по плану.
     */
    private fun onDegraded(core: DPpassCore, profileId: ProfileId, reason: Diagnostic, regime: NetworkAssessment?) {
        val prefs = AppPrefs(this)
        // Автопереключение выключено — сервер сессии закреплён, и замена только вопросом (D-113, D-58).
        val chosen = pinTarget(core) ?: prefs.selectedServer
        when (val d = core.degraded(profileId, reason, chosen, prefs.autoSwitch, synchronized(declined) { declined.toSet() }, regime)) {
            is Degradation.Reconnect -> Unit
            is Degradation.Ask -> {
                val shown = ServerSwitch.ask(this, d)
                core.log.info("server_switch_offered", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value), "notification" to shown)
            }
            is Degradation.Switch -> {
                prefs.selectedServer = d.to.id
                val shown = ServerSwitch.switched(this, d)
                core.log.info("server_switched", "from" to Safe(d.from.id.value), "to" to Safe(d.to.id.value), "by" to Safe("auto"), "notification" to shown)
            }
        }
    }

    /**
     * Раздача (D-51): раз в [SHARE_POLL_MILLIS] — какие интерфейсы раздачи
     * есть сейчас. Набор изменился (точку доступа или модем включили,
     * выключили, сменился адрес) — переподключение через [ACTION_RECONNECT]:
     * конфигурация ядра во время работы не меняется, новые входы — только
     * новым запуском.
     */
    private fun startShareWatch(core: DPpassCore, current: List<ShareSpec.Endpoint>) {
        shareWatch?.cancel()
        shareWatch = scope.launch {
            var previous: List<ShareSpec.Endpoint>? = null
            while (isActive) {
                delay(SHARE_POLL_MILLIS)
                // Наша ли ещё сессия: остановка или переподключение могли её сменить.
                if (state.withLock { session } == null) return@launch
                val wanted = TetherInterfaces.find(this@DPpassVpnService)
                if (TetherInterfaces.shouldReconnect(current, wanted, previous)) {
                    core.log.info("share_interfaces_changed", "was" to current.size, "now" to wanted.size)
                    reconnect(this@DPpassVpnService)
                    return@launch
                }
                previous = wanted
            }
        }
    }

    /**
     * Адреса раздачи для подключения (D-51): новый интерфейс — только виденный
     * двумя снимками подряд, как в опросе ([TetherInterfaces.confirmed]).
     * Пауза — только если раздавать есть на что.
     */
    private suspend fun tetherForConnect(): List<ShareSpec.Endpoint> {
        val first = TetherInterfaces.find(this)
        if (first.isEmpty()) {
            // Раздача включена, а интерфейсов нет: что видно — в журнал, без адресов (D-57).
            DeviceLog.log.info("share_no_tether", "seen" to Safe(TetherInterfaces.snapshot(this)))
            return first
        }
        delay(SHARE_CONFIRM_MILLIS)
        return TetherInterfaces.confirmed(first, TetherInterfaces.find(this))
    }

    /**
     * Сеть под туннелем (D-40): её тип и тарификацию видят система и
     * приложения, её смена — повод проверить новую сеть (D-67). Через
     * устройство раздачи (D-55) — его сеть [fixed]: туннель идёт по ней,
     * какая бы ни была сеть по умолчанию.
     *
     * Слушаются все сети без VPN, а не «сеть по умолчанию»: её колбэк на
     * телефоне о переходе Wi-Fi ↔ мобильная не сообщал (18.10.2026). При
     * каждом событии нынешняя сеть выбирается заново ([NetworkCheck.underlying]),
     * и только её смена что-то меняет.
     */
    private fun watchNetwork(fixed: Network? = null) {
        if (fixed != null) {
            // Через устройство раздачи режим оператора ни при чём (D-64): проверка после смены не нужна.
            changeCheck?.cancel()
            changeCheck = null
            setUnderlyingNetworks(arrayOf(fixed))
            DeviceLog.log.info("underlying_network", "state" to Safe("relay"))
            return
        }
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        // Смена сети (D-67): смены — на всё время сервиса, первая сеть — сеть подключения, не смена.
        val watch = changes ?: NetworkChangeChecks(Clock.MONOTONIC).also { changes = it }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        val callback = object : ConnectivityManager.NetworkCallback() {
            // Колбэки — по одному, в потоке системы: [current] трогает только он.
            private var current: Long? = null
            private var registered = false

            private fun update() {
                val u = NetworkCheck.underlying(this@DPpassVpnService)
                val handle = u.network?.networkHandle
                if (registered && handle == current) return
                val networkChanged = registered && handle != current
                val wasLost = registered && current == null
                registered = true
                // A strategy learned on LTE must not silently be reused on
                // another carrier/Wi-Fi or after a network outage. Keep the
                // explicit selections, but clear ephemeral per-host evidence.
                if (networkChanged) ServerAutoModel.resetTransient()
                if (networkChanged && AppPrefs(this@DPpassVpnService).zapret2Backend == Zapret2Backend.VPN_SERVICE) {
                    val result = runCatching {
                        JniXrayRuntime.configureZapret2AdaptiveHosts(
                            AppPrefs(this@DPpassVpnService).zapret2AdaptiveTargetsText)
                    }.getOrNull()
                    if (result == null || result is XrayResult.Failed) {
                        DeviceLog.log.warning("zapret2_adaptive_reset_failed", "reason" to Safe("network_change"))
                    } else {
                        DeviceLog.log.info("zapret2_adaptive_reset", "reason" to Safe("network_change"))
                    }
                    // Change the active head only. NEVER reload random weights
                    // on a handoff: MOBILE/Wi-Fi/OTHER learning is retained.
                    val networkClass = when (u.type) {
                        NetworkType.MOBILE -> "MOBILE"
                        NetworkType.WIFI -> "WIFI"
                        else -> "OTHER"
                    }
                    val updated = runCatching {
                        JniXrayRuntime.configureZapret2NeuralNetwork(networkClass)
                    }.getOrNull()
                    if (updated == null || updated is XrayResult.Failed) {
                        DeviceLog.log.warning("zapret2_neural_context_failed",
                            "reason" to Safe("network_change"))
                    }
                }
                val from = underlyingType
                current = handle
                underlyingType = u.type
                setUnderlyingNetworks(u.network?.let { arrayOf(it) })
                DeviceLog.log.info("underlying_network", "state" to Safe(if (handle == null) "lost" else "available"), "type" to u.type)
                if (handle != null && watch.onNetwork(handle)) onNetworkChanged(watch, handle, from, u.type)
                // Сеть вернулась после пропажи (D-113): сервер не менялся, соединение — восстановить.
                if (handle != null && wasLost) onNetworkRestored()
            }

            override fun onAvailable(network: Network) = update()

            override fun onLost(network: Network) = update()

            // Система проверила сеть или сменила свою по умолчанию — без новых onAvailable/onLost.
            override fun onCapabilitiesChanged(network: Network, networkCapabilities: NetworkCapabilities) = update()
        }
        try {
            cm.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (e: RuntimeException) {
            // Слишком много колбэков у процесса или нет разрешения — туннель работает и без этого.
            DeviceLog.log.diagnostic(Diagnostic.fromThrowable(DiagCode.INTERNAL_ERROR, "сеть под туннелем не отслеживается", e))
        }
    }

    /** Есть ли сеть под туннелем (D-113); через устройство раздачи (D-55) путь свой — считаем, что есть. */
    private fun networkUp(): Boolean = viaRelay || NetworkCheck.underlying(this).network != null

    /**
     * Сервер, который сессия обязана держать (D-113): автопереключение выключено —
     * выбранный пользователем, а в режиме «Автоматически» — тот, к которому
     * подключились. null — переключение разрешено (тумблер включён) или держать
     * пока нечего. Выбор, которого нет в конфигурации (подписка обновилась),
     * не действует — как на экране серверов.
     */
    private fun pinTarget(core: DPpassCore): ProfileId? {
        val prefs = AppPrefs(this)
        if (prefs.autoSwitch) return null
        // Explicit opt-in server-auto MLP means no silent reuse of the last
        // connected server as a hard pin during subsequent starts.
        if (prefs.selectedServer == null &&
            Zapret2NeuralModel.isInstalled(this, Zapret2NeuralModel.Kind.SERVER)) return null
        val present = core.activation.state.activeConfig?.profiles?.map { it.id }.orEmpty()
        return prefs.selectedServer?.takeIf { it in present } ?: pinned?.takeIf { it in present }
    }

    private fun cancelRecovery() {
        recovery?.cancel()
        recovery = null
    }

    /** Сеть вернулась (D-113): подождать, пока она устоится, и переподключиться к тому же серверу. */
    private fun onNetworkRestored() {
        val core = AppGraph.core(this)
        core.log.info("network_restored")
        startRecovery(core, null)
    }

    /**
     * Восстановление соединения (D-113): ждёт сеть, переподключает — к тому же
     * серверу при выключенном автопереключении, с растущей паузой
     * ([Recovery]). Сервер молча не меняется; не вышло за [Recovery.NOTIFY_AFTER]
     * попыток при живой сети — уведомление с причиной и предложением сменить
     * сервер, решение за пользователем. VPN не отключается: TUN остаётся (D-111).
     * Пока сеть пропала, попытки не делаются и отказов в журнал здоровья не пишут.
     */
    private fun startRecovery(core: DPpassCore, first: Diagnostic?) {
        if (recovery?.isActive == true) return
        recovery = scope.launch {
            var failure = first
            var failedAttempts = 0
            // Сеть вернулась при поднятом туннеле — переподключаемся сразу; после отказа — по паузе.
            var settle = first == null
            var waiting = false
            while (isActive) {
                if (!networkUp()) {
                    if (!waiting) core.log.info("recovery_waiting_network")
                    waiting = true
                    delay(Recovery.NETWORK_POLL_MILLIS)
                    continue
                }
                waiting = false
                delay(if (settle) Recovery.SETTLE_MILLIS else Recovery.delayMillis(failedAttempts))
                settle = false
                // Сеть успела пропасть за паузу — снова ждать её, а не пробовать вхолостую.
                if (!networkUp()) continue
                core.log.info("recovery_attempt", "n" to failedAttempts + 1)
                restarts.incrementAndGet()
                restart()
                while (isActive && TunnelState.status.value is TunnelStatus.Connecting) delay(Recovery.STATUS_POLL_MILLIS)
                val status = TunnelState.status.value
                val outcome = Recovery.afterAttempt(
                    connected = status is TunnelStatus.Connected,
                    blockedFailure = status is TunnelStatus.Failed && status.trafficBlocked,
                    networkUp = networkUp(),
                )
                when (outcome) {
                    Recovery.AttemptResult.RESTORED -> {
                        core.log.info("recovery_done", "attempts" to failedAttempts + 1)
                        ServerSwitch.clear(this@DPpassVpnService)
                        return@launch
                    }
                    // Успех ядра при уже пропавшей сети ещё не означает восстановление (D-113).
                    Recovery.AttemptResult.WAIT_FOR_NETWORK -> continue
                    // Остановлено или сервис ушёл (нет TUN) — восстанавливать нечего.
                    Recovery.AttemptResult.STOP -> return@launch
                    Recovery.AttemptResult.RETRY -> {
                        failure = (status as TunnelStatus.Failed).reason
                        // Потеря сети во время обработки отказа — не ошибка сервера.
                        if (!networkUp()) continue
                        failedAttempts++
                        if (failedAttempts == Recovery.NOTIFY_AFTER) offerChange(core, failure)
                    }
                }
            }
        }
    }

    /**
     * Соединиться не удаётся, а сеть есть (D-113): сообщить причину. Автопереключение
     * выключено — сервер не меняется, предлагается замена с кнопками «Перейти» и
     * «Остаться»; замены нет или о ней уже ответили «Остаться» — просто сообщение.
     */
    private fun offerChange(core: DPpassCore, reason: Diagnostic) {
        val ir = core.activation.state.activeConfig
        val from = pinTarget(core)?.let { id -> ir?.profiles?.firstOrNull { it.id == id } }
        val to = from?.let { core.alternativeTo(it.id, sessionRegime) }
        val shown = if (from != null && to != null && from.id !in synchronized(declined) { declined.toSet() }) {
            ServerSwitch.ask(this, Degradation.Ask(from, to, reason), unreachable = true)
        } else {
            ServerSwitch.unreachable(this, from, reason)
        }
        core.log.info("server_unreachable_notified", "profile" to Safe(from?.id?.value ?: "-"), "offer" to (to != null), "notification" to shown)
    }

    /**
     * Сеть под туннелем сменилась (D-67). Режим сессии — заново: у новой сети
     * он неизвестен, пока её не проверили. Через паузу ([NetworkChangeChecks])
     * — проверка новой сети, той же, что по кнопке (D-60), и режим ещё раз:
     * под белым списком новой сети опыт сессии — его. Пропуск проверки — с
     * причиной в журнале: выключено, сеть уже другая, предел за час.
     */
    private fun onNetworkChanged(changes: NetworkChangeChecks, network: Long, from: NetworkType, to: NetworkType) {
        val core = AppGraph.core(this)
        core.log.info("network_changed", "from" to from, "to" to to)
        val backend = AppPrefs(this).zapret2Backend
        if ((backend == Zapret2Backend.VPN_SERVICE || backend == Zapret2Backend.BYEDPI_VPN) &&
            from != NetworkType.NONE && to != NetworkType.NONE &&
            (from == NetworkType.MOBILE) != (to == NetworkType.MOBILE)) {
            // Recompile the local DNS address-family policy for the new network.
            reconnect(this)
            return
        }
        retakeRegime(core, "network_changed")
        changeCheck?.cancel()
        changeCheck = scope.launch {
            while (true) {
                // null — сеть уже другая: её проверит своя смена.
                val wait = changes.waitMillis(network) ?: return@launch
                if (wait == 0L) break
                delay(wait)
            }
            if (!AppPrefs(this@DPpassVpnService).checkOnNetworkChange) {
                core.log.info("network_check_skipped", "reason" to Safe("disabled"))
                return@launch
            }
            // Проверка по кнопке только что потратила бюджет (D-14): подождать, а не идти с пропусками.
            delay(NetworkCheck.readyInMillis())
            val skipped = when {
                changes.waitMillis(network) == null -> "network_gone"
                !changes.tryStart(network) -> "limit"
                else -> null
            }
            if (skipped != null) {
                core.log.info("network_check_skipped", "reason" to Safe(skipped))
                return@launch
            }
            if (NetworkCheck.run(this@DPpassVpnService, core.log, NetworkCheck.Trigger.NETWORK_CHANGE) == null) {
                // Идёт проверка по кнопке — её итог и будет итогом новой сети.
                while (NetworkCheck.busy()) delay(BUSY_POLL_MILLIS)
            }
            retakeRegime(core, "network_checked")
        }
    }

    /** Режим сессии — по памяти режима для нынешней сети (D-64, D-67): белый список или неизвестен. */
    private fun retakeRegime(core: DPpassCore, reason: String) {
        val regime = NetworkCheck.regime(this)
        sessionRegime = regime
        core.log.info("network_regime_retaken", "reason" to Safe(reason), "class" to (regime?.restriction ?: RestrictionClass.UNKNOWN))
    }

    private fun unwatchNetwork() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (e: RuntimeException) {
            // Уже снят.
        }
    }

    /** Отказ запуска: причина — в журнал и на экран, сервис уходит. */
    private fun fail(reason: Diagnostic) {
        AppGraph.core(this).log.diagnostic(reason)
        val blocked = tunnel.present
        TunnelState.set(TunnelStatus.Failed(reason, trafficBlocked = blocked))
        announce()
        if (blocked) startInForeground(TunnelState.status.value) else stopSelf()
    }

    /** Новое состояние подключения — и в уведомление: его видно и без экрана. */
    private fun progress(status: TunnelStatus) {
        TunnelState.set(status)
        announce()
        startInForeground(status)
    }

    /**
     * Ядро — потом TUN; повторный вызов ничего не делает. Прежнее подключение
     * отменяется и дожидается: его проба здоровья — блокирующий вызов ядра
     * (до срока пробы), и запущенный им сеанс останавливается, только когда
     * она вернётся. Вызывается под [lifecycle].
     */
    /**
     * Only a successful atomic write may clear native "dirty". New traffic
     * can train concurrently with disk I/O; the native acknowledgement
     * compares the exact snapshot and preserves newer learning if it differs.
     */
    private fun persistStrategyLearning() {
        val kind = Zapret2NeuralModel.Kind.STRATEGY
        val current = Zapret2NeuralModel.readVerified(this, kind) ?: return
        val snapshot = runCatching { JniXrayRuntime.snapshotZapret2NeuralModel() }
            .getOrElse {
                DeviceLog.log.warning("zapret2_neural_persist_failed",
                    "reason" to Safe("native_snapshot_failed"))
                return
            }
        if (snapshot == null) {
            // No qualifying >=12-KiB per-flow outcome may mean zero updates.
            // Log durable counters to make the absence of training visible.
            runCatching {
                val model = org.json.JSONObject(current.decodeToString())
                DeviceLog.log.info("zapret2_neural_progress",
                    "observations" to model.optInt("observations", 0),
                    "sparse" to (model.optJSONObject("sparse")?.length() ?: 0),
                    "updated" to false)
            }
            return
        }
        if (!Zapret2NeuralModel.storeLearnedSnapshot(this, kind, snapshot)) {
            DeviceLog.log.warning("zapret2_neural_persist_failed",
                "reason" to Safe("stale_or_disk_write_failed"))
            return
        }
        val ack = runCatching { JniXrayRuntime.acknowledgeZapret2NeuralModel(snapshot) }.getOrNull()
        if (ack == null || ack is XrayResult.Failed) {
            // A newer native update may have happened since the snapshot.
            // It remains dirty for retry at the next window/shutdown.
            DeviceLog.log.info("zapret2_neural_newer_update_pending")
        }
        runCatching {
            val model = org.json.JSONObject(snapshot.decodeToString())
            DeviceLog.log.info("zapret2_neural_saved",
                "observations" to model.optInt("observations", 0),
                "sparse" to (model.optJSONObject("sparse")?.length() ?: 0),
                "bytes" to snapshot.size)
        }
    }

    private fun stopObservers() {
        supervisor?.cancel()
        supervisor = null
        shareWatch?.cancel()
        shareWatch = null
        ticker?.cancel()
        ticker = null
        // Save before Xray stops, including fast reconnects under 30 seconds.
        if (zapret2FinalState != null) runCatching { persistStrategyLearning() }
        // A reconnect may happen before the first 30-second transfer window.
        // Emit the whole-session snapshot while the old engine is still alive,
        // and at most once even when shutdown invokes stopObservers twice.
        val final = zapret2FinalState
        zapret2FinalState = null
        if (final != null) {
            runCatching {
                val current = final.session.stats()
                val probes = AppGraph.graph(this).engine.desyncCounters()
                val summary = final.counters.finish(
                    current.uplinkBytes, current.downlinkBytes,
                    probes?.applied ?: 0L, probes?.skipped ?: 0L,
                )
                if (summary != null) AppGraph.core(this).log.info("zapret2_transfer_final",
                    "duration_ms" to (Clock.MONOTONIC.nowMillis() - final.startedMillis).coerceAtLeast(0L),
                    "up_bytes" to summary.upBytes,
                    "down_bytes" to summary.downBytes,
                    "applied_delta" to summary.appliedDelta,
                    "skipped_delta" to summary.skippedDelta,
                    "applied_total" to summary.appliedTotal,
                    "skipped_total" to summary.skippedTotal)
                val finalStages = AppGraph.graph(this).engine.zapret2Stages()
                if (final.initialStages != null && finalStages != null) {
                    logZapret2Stages("zapret2_stage_final", finalStages.delta(final.initialStages))
                }
            }.onFailure {
                DeviceLog.log.warning("zapret2_transfer_final_unavailable",
                    "reason" to Safe(it.javaClass.simpleName))
            }
        }
        unwatchNetwork()
        TunnelState.share(emptyList())
    }

    private suspend fun shutdown(keepTunnel: Boolean = false) {
        alpineWatch?.cancel()
        alpineWatch = null
        byeDpiWatch?.cancel()
        byeDpiWatch = null
        rootWatch?.cancel()
        rootWatch = null
        stopObservers()
        state.withLock {
            sessionRegime = null
            val pending = connecting
            connecting = null
            pending?.cancel()
            session?.stop()
            session = null
            pending
        }?.join()
        withContext(Dispatchers.IO) { runCatching { byeDpi?.close() } }
        byeDpi = null
        // The protected-socket engine must stop before the Alpine strategy
        // daemon. Clear the socket to avoid stale state in the next session.
        if (alpineStrategy != null) {
            runCatching { JniXrayRuntime.configureZapret2Planner(null) }
            runCatching { alpineStrategy?.close() }
            alpineStrategy = null
        }
        // У root нет Xray EngineSession, но есть собственный процесс и NFQUEUE.
        rootZapret2?.stop()?.onFailure { error ->
            DeviceLog.log.diagnostic(Diagnostic.fromThrowable(
                DiagCode.BACKEND_NOT_AVAILABLE, "не удалось снять правила Zapret2 при остановке", error,
            ))
        }
        rootZapret2 = null
        // NonCancellable acceptance мог зарегистрировать наблюдателей после первой отмены.
        stopObservers()
        // establish мог завершиться после отмены: fd уже принадлежит владельцу.
        // Явная остановка закрывает его после завершения подключения; restart сохраняет блокировку.
        if (!keepTunnel) tunnel.close()
        // Опыт адаптивной модели — на диск, чтобы пережил остановку (D-44); счёт трафика — тоже (D-92).
        withContext(NonCancellable) {
            val core = AppGraph.graph(this@DPpassVpnService).core
            core.persistStability()
            core.usage.flush().diagnostics.forEach(core.log::diagnostic)
            core.analyzer.flush().diagnostics.forEach(core.log::diagnostic)
        }
    }

    override fun onRevoke() {
        // Пользователь отозвал разрешение или включил другой VPN.
        DeviceLog.log.info("service_revoked")
        scope.launch {
            lifecycle.withLock { shutdown() }
            TunnelState.set(TunnelStatus.Idle)
            announce()
            stopSelf()
        }
    }

    override fun onDestroy() {
        // Сервис уходит: уборка — в области процесса, она переживёт этот объект.
        val failed = TunnelState.status.value as? TunnelStatus.Failed
        AppGraph.scope.launch {
            lifecycle.withLock { shutdown() }
            if (failed?.trafficBlocked == true && TunnelState.status.value === failed) {
                TunnelState.set(failed.copy(trafficBlocked = false))
                announce()
            }
        }
        // Без туннеля вопрос о сбое сервера (D-58) ни к чему.
        ServerSwitch.clear(this)
        // Отказ остаётся на экране; всё остальное без сервиса — «не подключено».
        if (TunnelState.status.value !is TunnelStatus.Failed) TunnelState.set(TunnelStatus.Idle)
        announce()
        // Сервис остановлен — отмечаем в журнале; экспорт только по кнопке (D-47).
        DeviceLog.onWorkFinished(this, "service_stop")
        scope.cancel()
        super.onDestroy()
    }

    /** Плитка быстрых настроек показывает состояние, только пока её слушают: попросить обновиться. */
    private fun announce() {
        try {
            TileService.requestListeningState(this, ComponentName(this, DPpassTileService::class.java))
        } catch (e: RuntimeException) {
            // Плитки нет в шторке — некому показывать.
        }
    }

    /**
     * Уведомление foreground-сервиса. Ложь — система не дала стать
     * foreground (Android 12+ из фона); тогда сервис уходит с причиной.
     */
    private fun startInForeground(status: TunnelStatus, traffic: Traffic? = null): Boolean {
        val n = notification(status, traffic)
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(NOTIFICATION_ID, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
            } else {
                startForeground(NOTIFICATION_ID, n)
            }
        } catch (e: IllegalStateException) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && e is ForegroundServiceStartNotAllowedException) {
                DeviceLog.log.diagnostic(Diagnostic.fromThrowable(DiagCode.TUN_ESTABLISH_FAILED, "система не разрешила сервису туннеля работать из фона", e))
                TunnelState.set(TunnelStatus.Failed(Diagnostic.error(DiagCode.TUN_ESTABLISH_FAILED, "система не разрешила запуск туннеля из фона")))
                stopSelf()
                return false
            }
            throw e
        }
        return true
    }

    private fun notification(status: TunnelStatus, traffic: Traffic?): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW))
        val units = resources.getStringArray(R.array.units_bytes).toList()
        val locale = resources.configuration.locales[0]
        val text = when (status) {
            is TunnelStatus.Connected -> if (traffic != null && (traffic.downPerSec > 0 || traffic.upPerSec > 0)) {
                getString(
                    R.string.notification_connected_traffic,
                    status.profileName,
                    Formats.speed(traffic.downPerSec, units, locale, getString(R.string.per_second)),
                    Formats.speed(traffic.upPerSec, units, locale, getString(R.string.per_second)),
                )
            } else {
                getString(R.string.notification_connected, status.profileName)
            }
            is TunnelStatus.Failed -> getString(if (status.trafficBlocked) R.string.vpn_blocked_note else R.string.status_failed)
            is TunnelStatus.Connecting -> status.profileName?.let { getString(R.string.notification_checking, it) }
                ?: getString(R.string.notification_connecting)
            else -> getString(R.string.notification_connecting)
        }
        val open = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        val stop = PendingIntent.getService(
            this,
            1,
            Intent(this, DPpassVpnService::class.java).setAction(ACTION_STOP),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
        )
        // На заблокированном экране — только «DPpass подключён», без имени сервера (T9):
        // имя часто называет страну и поставщика.
        val public = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(R.string.app_name))
            .setContentText(
                getString(
                    when {
                        status is TunnelStatus.Connected -> R.string.notification_public_connected
                        status is TunnelStatus.Failed && status.trafficBlocked -> R.string.status_blocked
                        else -> R.string.notification_connecting
                    },
                ),
            )
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .build()
        val b = Notification.Builder(this, CHANNEL)
            .setContentTitle(getString(if (status is TunnelStatus.Connected) R.string.notification_title_connected else R.string.app_name))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat_tunnel)
            .setContentIntent(open)
            .addAction(Notification.Action.Builder(Icon.createWithResource(this, R.drawable.ic_power), getString(R.string.action_disconnect), stop).build())
            .setVisibility(Notification.VISIBILITY_PRIVATE)
            .setPublicVersion(public)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(Notification.CATEGORY_SERVICE)
        // Без VPN (D-95): куда направить приложения — адрес и порт, без логина и пароля.
        TunnelState.localProxy.value?.takeIf { status is TunnelStatus.Connected }?.let { b.setSubText(getString(R.string.local_proxy_connected, it.port)) }
        if (status is TunnelStatus.Connected) {
            // Время с подключения считает сама шторка — без обновлений уведомления.
            b.setWhen(status.sinceMillis).setShowWhen(true).setUsesChronometer(true)
        } else {
            b.setShowWhen(false)
        }
        return b.build()
    }

    companion object {
        const val ACTION_STOP: String = "com.dpsmpx.dppass.action.STOP"
        const val ACTION_RECONNECT: String = "com.dpsmpx.dppass.action.RECONNECT"
        const val ACTION_SWITCH: String = "com.dpsmpx.dppass.action.SWITCH_SERVER"
        const val ACTION_KEEP: String = "com.dpsmpx.dppass.action.KEEP_SERVER"
        private const val EXTRA_PROFILE = "profile"
        private const val EXTRA_BY_USER = "by_user"
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1
        private const val PROBE_MARGIN_MILLIS = 2_000L

        /** Наблюдатель сессии (D-44): период пробы здоровья и как часто сохранять модель. */
        private const val SUPERVISION_INTERVAL_MILLIS = 15_000L
        private const val PERSIST_EVERY_SAMPLES = 8

        /** Опрос анализатора для журнала уникальных (D-106): раз в 10 тиков, то есть в 10 с. */
        private const val ANALYZER_EVERY_TICKS = 10L

        /** Проверка новой сети (D-67) ждёт проверку по кнопке, начатую раньше: как часто смотреть, кончилась ли. */
        private const val BUSY_POLL_MILLIS = 1_000L

        /** Проб IPv6 за сессию (D-66), если итог «не понять»: потом строка «проверить не удалось». */
        private const val IPV6_TRIES = 3

        /** Раздача (D-51): как часто проверять интерфейсы раздачи (docs/PERFORMANCE_BUDGET.md). */
        private const val SHARE_POLL_MILLIS = 5_000L

        /** Между двумя снимками интерфейсов раздачи при подключении (D-51): короче опроса — подключение не ждёт 5 с. */
        private const val SHARE_CONFIRM_MILLIS = 1_500L

        fun start(context: Context) {
            context.startForegroundService(Intent(context, DPpassVpnService::class.java))
        }

        fun stop(context: Context) {
            context.startService(Intent(context, DPpassVpnService::class.java).setAction(ACTION_STOP))
        }

        /** [byUser] — выбор пользователя (сервер, «Автоматически»): закрепление сервера (D-113) сбрасывается. */
        fun reconnect(context: Context, byUser: Boolean = false) {
            context.startForegroundService(Intent(context, DPpassVpnService::class.java).setAction(ACTION_RECONNECT).putExtra(EXTRA_BY_USER, byUser))
        }

        /** Ответ «Перейти» (D-58): [to] становится выбранным сервером. */
        fun switchIntent(context: Context, to: ProfileId): Intent =
            Intent(context, DPpassVpnService::class.java).setAction(ACTION_SWITCH).putExtra(EXTRA_PROFILE, to.value)

        /** Ответ «Остаться» (D-58) о сервере [from]. */
        fun keepIntent(context: Context, from: ProfileId): Intent =
            Intent(context, DPpassVpnService::class.java).setAction(ACTION_KEEP).putExtra(EXTRA_PROFILE, from.value)
    }
}
