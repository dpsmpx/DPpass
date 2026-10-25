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
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.Degradation
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.connection.ServerlessSettings
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
import com.dpsmpx.dppass.engine.ServerlessPlan
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SocketProtector
import com.dpsmpx.dppass.engine.xray.Ipv6Egress
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkChangeChecks
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.RestrictionClass
import com.dpsmpx.dppass.routing.SplitSites
import com.dpsmpx.dppass.tunnel.Ipv6Mode
import com.dpsmpx.dppass.tunnel.TunnelHandle
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
    private var tunnel: TunnelHandle? = null
    private var ticker: Job? = null
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

    /** Серверы, о которых пользователь ответил «Остаться» (D-58): до остановки туннеля, то есть этого сервиса. */
    private val declined: MutableSet<ProfileId> = Collections.synchronizedSet(HashSet())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_SWITCH -> {
                ServerSwitch.clear(this)
                val to = intent.getStringExtra(EXTRA_PROFILE)?.takeIf(Ids::isValid)?.let(::ProfileId)
                if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
                restarts.incrementAndGet()
                scope.launch {
                    val core = AppGraph.core(this@DPpassVpnService)
                    if (core.activation.state.activeConfig == null) core.restore()
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
                DeviceLog.log.info("service_reconnect")
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
            shutdown()
            if (restarts.decrementAndGet() == 0) start() else DeviceLog.log.info("service_reconnect_superseded")
        }
    }

    private suspend fun start() {
        state.withLock {
            if (connecting?.isActive == true || session != null) {
                DeviceLog.log.info("service_already_running")
                return
            }
            TunnelState.set(TunnelStatus.Connecting(null))
            announce()
            connecting = scope.launch { connect() }
        }
    }

    private suspend fun connect() {
        val graph = AppGraph.graph(this)
        val core = graph.core
        if (core.activation.state.activeConfig == null) core.restore()
        // Устройство раздачи (D-55): выбрано — подключение только через него, по сети, где оно ответило.
        val relay = AppPrefs(this).selectedRelay?.let(core.relays::find)
        val target = relay?.let { d ->
            when (val t = withContext(Dispatchers.IO) { RelayNetworks.locate(this@DPpassVpnService, d) }) {
                is Outcome.Failure -> {
                    fail(t.errors.first())
                    return
                }
                is Outcome.Success -> t.value.also { core.log.info("relay_found", "medium" to Safe(it.medium.name), "auto" to (d.address == null)) }
            }
        }
        // Без сервера (D-73): серверов нет, устройство раздачи не выбрано, а сайтам списка нужен туннель.
        val prefs = AppPrefs(this)
        val sites = prefs.splitSites()
        val serverless = prefs.serverless
        if (core.serverlessReady(sites, serverless, relaySelected = relay != null)) {
            connectServerless(graph, sites, serverless)
            return
        }
        val ir = if (relay != null && target != null) core.relayConfig(relay, target.address) else core.activation.state.activeConfig
        val spec = ir?.let(core::tunnelSpecFor)
        if (ir == null || spec == null) {
            fail(Diagnostic.error(DiagCode.PROFILES_EMPTY, "нет активной конфигурации — туннель не поднимается"))
            return
        }
        val tunSpec = when (spec) {
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
        core.log.info("tunnel_up", "routes" to tunSpec.routes.size, "apps" to Safe(tunSpec.apps::class.simpleName ?: "?"))
        // Проба здоровья (D-32) блокирует поток — не дольше своего срока, меньше срока плана.
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val checker = HealthChecker { _, profile ->
            progress(TunnelStatus.Connecting(profile.name))
            withContext(Dispatchers.IO) { graph.engine.probeHealth(ir.dns, probeTimeout) }
        }
        val preferred = AppPrefs(this).selectedServer
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
            val tun = handle.toTunInput().let { base ->
                // Сокеты ядра — в сеть устройства раздачи: с Bluetooth- и USB-модема путь к нему не по умолчанию.
                if (target == null) {
                    base
                } else {
                    base.copy(protector = SocketProtector { fd -> base.protector.protect(fd) && RelayNetworks.bind(target.network, fd) })
                }
            }
            if (relay != null && target != null) {
                core.connectVia(relay, target.address, checker, tun, share) { delay(it) }
            } else {
                // Разбиение ClientHello к серверу (D-68) — выбор пользователя; к устройству раздачи — нет.
                val split = prefs.splitClientHello
                core.log.info("client_hello_split", "on" to split)
                // Сайты напрямую с разбиением (D-72): в журнал — число записей, не сами сайты.
                core.log.info("split_sites", "n" to sites.size)
                core.connect(null, checker, tun, preferred, share, regime, split, sites) { delay(it) }
            }
        } catch (e: CancellationException) {
            // Остановка во время подключения: сеанс, запущенный посреди проверки
            // здоровья, оркестратор уже остановил (ConnectionOrchestrator.tryOne);
            // остаётся TUN.
            handle.close()
            throw e
        }
        // План и исходы попыток — для «Почему этот сервер» (D-15), и при отказе тоже.
        report?.let { TunnelState.plan(PlanSnapshot(core.clock.nowMillis(), it.attempts, it.plan.excluded, viaRelay = relay != null)) }
        when (report) {
            is ConnectionReport.Connected -> withContext(NonCancellable) {
                // Вызовы ядра не прерываются отменой: остановка могла прийти, пока
                // шёл запуск. Тогда сеанс не принимается, а сразу останавливается.
                val accepted = state.withLock {
                    if (job.isCancelled) {
                        false
                    } else {
                        session = report.session
                        tunnel = handle
                        true
                    }
                }
                if (accepted) {
                    core.log.info("connected", "profile" to Safe(report.profileId.value), "attempts" to report.attempts.size)
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
                    progress(TunnelStatus.Connected(report.profileId, name, core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
                    // Режим сессии — до того, как колбэк сети может взять его заново (D-67).
                    sessionRegime = if (contradicted) null else regime
                    watchNetwork(target?.network)
                    startTicker(report.session)
                    // IPv6 через сервер (D-66): только когда TUN его берёт и путь — свой сервер, а не устройство раздачи.
                    val checkIpv6 = relay == null && tunSpec.ipv6Mode == Ipv6Mode.TUNNELED
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
                    handle.close()
                }
            }
            is ConnectionReport.Failed -> {
                handle.close()
                fail(report.reason)
            }
            null -> {
                handle.close()
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
    private suspend fun connectServerless(graph: AppGraph.Graph, sites: SplitSites, settings: ServerlessSettings) {
        val core = graph.core
        val name = getString(R.string.serverless_name)
        val tunSpec = when (val spec = core.tunnelSpecFor(core.serverlessConfig(settings))) {
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
        core.log.info("tunnel_up", "routes" to tunSpec.routes.size, "apps" to Safe(tunSpec.apps::class.simpleName ?: "?"))
        progress(TunnelStatus.Connecting(name))
        val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
        val job = currentCoroutineContext().job
        val result = try {
            core.connectServerless(handle.toTunInput(), sites, settings) { _, dns ->
                withContext(Dispatchers.IO) { graph.engine.probeServerless(dns, probeTimeout) }
            }
        } catch (e: CancellationException) {
            handle.close()
            throw e
        }
        when (result) {
            is Outcome.Failure -> {
                handle.close()
                fail(result.errors.first())
            }
            is Outcome.Success -> withContext(NonCancellable) {
                val session = result.value
                val accepted = state.withLock {
                    if (job.isCancelled) {
                        false
                    } else {
                        this@DPpassVpnService.session = session
                        tunnel = handle
                        true
                    }
                }
                if (accepted) {
                    core.log.info("connected", "profile" to Safe(ServerlessPlan.PROFILE_ID.value), "attempts" to 1)
                    progress(TunnelStatus.Connected(ServerlessPlan.PROFILE_ID, name, core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
                    watchNetwork()
                    startTicker(session)
                } else {
                    session.stop()
                    handle.close()
                }
            }
        }
    }

    /**
     * Счётчики ядра → скорость и итоги (D-40). Раз в секунду, пока экран
     * включён; уведомление — реже: каждое обновление стоит батареи.
     */
    private fun startTicker(session: EngineSession) {
        ticker?.cancel()
        ticker = scope.launch {
            val meter = TrafficMeter()
            val pace = NotificationPace()
            val power = getSystemService(PowerManager::class.java)
            val core = AppGraph.core(this@DPpassVpnService)
            // Учёт трафика (D-92) — и с выключенным экраном: приращения сеанса, сеть — та, что под туннелем.
            val usage = UsageMeter()
            while (isActive) {
                core.usage.record(usage.delta(session.stats()), underlyingType)?.let { UsageAlerts.show(this@DPpassVpnService, core, it) }
                val interactive = power.isInteractive
                val notify = pace.tick(interactive)
                if (interactive) {
                    val traffic = meter.sample(session.stats(), Clock.MONOTONIC.nowMillis())
                    TunnelState.traffic(traffic)
                    if (notify) (TunnelState.status.value as? TunnelStatus.Connected)?.let { startInForeground(it, traffic) }
                } else {
                    // Экран выключен: никто не смотрит — отсчёт скорости заново после включения.
                    meter.reset()
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
                val started = Clock.MONOTONIC.nowMillis()
                val result = withContext(Dispatchers.IO) { engine.probeHealth(ir.dns, probeTimeout) }
                val elapsed = (Clock.MONOTONIC.nowMillis() - started).coerceAtLeast(1)
                val failed = result is Outcome.Failure
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
        when (val d = core.degraded(profileId, reason, prefs.selectedServer, prefs.autoSwitch, synchronized(declined) { declined.toSet() }, regime)) {
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
                registered = true
                val from = underlyingType
                current = handle
                underlyingType = u.type
                setUnderlyingNetworks(u.network?.let { arrayOf(it) })
                DeviceLog.log.info("underlying_network", "state" to Safe(if (handle == null) "lost" else "available"), "type" to u.type)
                if (handle != null && watch.onNetwork(handle)) onNetworkChanged(watch, handle, from, u.type)
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
        TunnelState.set(TunnelStatus.Failed(reason))
        announce()
        stopSelf()
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
    private suspend fun shutdown() {
        supervisor?.cancel()
        supervisor = null
        shareWatch?.cancel()
        shareWatch = null
        TunnelState.share(emptyList())
        state.withLock {
            ticker?.cancel()
            ticker = null
            unwatchNetwork()
            sessionRegime = null
            val pending = connecting
            connecting = null
            pending?.cancel()
            session?.stop()
            session = null
            tunnel?.close()
            tunnel = null
            pending
        }?.join()
        // Опыт адаптивной модели — на диск, чтобы пережил остановку (D-44); счёт трафика — тоже (D-92).
        withContext(NonCancellable) {
            val core = AppGraph.graph(this@DPpassVpnService).core
            core.persistStability()
            core.usage.flush().diagnostics.forEach(core.log::diagnostic)
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
        AppGraph.scope.launch { lifecycle.withLock { shutdown() } }
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
            .setContentText(getString(if (status is TunnelStatus.Connected) R.string.notification_public_connected else R.string.notification_connecting))
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
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1
        private const val PROBE_MARGIN_MILLIS = 2_000L

        /** Наблюдатель сессии (D-44): период пробы здоровья и как часто сохранять модель. */
        private const val SUPERVISION_INTERVAL_MILLIS = 15_000L
        private const val PERSIST_EVERY_SAMPLES = 8

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

        fun reconnect(context: Context) {
            context.startForegroundService(Intent(context, DPpassVpnService::class.java).setAction(ACTION_RECONNECT))
        }

        /** Ответ «Перейти» (D-58): [to] становится выбранным сервером. */
        fun switchIntent(context: Context, to: ProfileId): Intent =
            Intent(context, DPpassVpnService::class.java).setAction(ACTION_SWITCH).putExtra(EXTRA_PROFILE, to.value)

        /** Ответ «Остаться» (D-58) о сервере [from]. */
        fun keepIntent(context: Context, from: ProfileId): Intent =
            Intent(context, DPpassVpnService::class.java).setAction(ACTION_KEEP).putExtra(EXTRA_PROFILE, from.value)
    }
}
