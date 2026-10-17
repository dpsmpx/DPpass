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
import com.dpsmpx.dppass.connection.SessionSupervisor
import com.dpsmpx.dppass.connection.StabilityObservation
import com.dpsmpx.dppass.connection.toTunInput
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.Ids
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.ShareSpec
import com.dpsmpx.dppass.engine.SocketProtector
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
 * Пока туннель поднят: сеть под ним — `setUnderlyingNetworks` по сети по
 * умолчанию (система и приложения видят её тип и тарификацию); счётчики
 * ядра раз в секунду → [TunnelState.traffic], уведомление — раз в
 * [NOTIFY_EVERY] секунды и только при включённом экране.
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
 */
class DPpassVpnService : VpnService() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    /** Состояние туннеля меняется только под этим замком: запуск и остановка не пересекаются. */
    private val state = Mutex()
    private var connecting: Job? = null
    private var session: EngineSession? = null
    private var tunnel: TunnelHandle? = null
    private var ticker: Job? = null
    private var supervisor: Job? = null
    private var shareWatch: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    /** Серверы, о которых пользователь ответил «Остаться» (D-58): до остановки туннеля, то есть этого сервиса. */
    private val declined: MutableSet<ProfileId> = Collections.synchronizedSet(HashSet())

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_SWITCH -> {
                ServerSwitch.clear(this)
                val to = intent.getStringExtra(EXTRA_PROFILE)?.takeIf(Ids::isValid)?.let(::ProfileId)
                if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
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
                    shutdown()
                    start()
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
                    shutdown()
                    TunnelState.set(TunnelStatus.Idle)
                    announce()
                    stopSelf()
                }
                return START_NOT_STICKY
            }
            ACTION_RECONNECT -> {
                DeviceLog.log.info("service_reconnect")
                if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
                scope.launch {
                    shutdown()
                    start()
                }
                return START_STICKY
            }
        }
        // Свой запуск, always-on (действие VpnService) или перезапуск после гибели процесса (интента нет).
        DeviceLog.log.info("service_start", "by" to Safe(if (intent == null) "restart" else intent.action ?: "app"))
        if (!startInForeground(TunnelStatus.Connecting(null))) return START_NOT_STICKY
        scope.launch { start() }
        return START_STICKY
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
        // Раздача (D-51): входы — на адресах интерфейсов раздачи, если пользователь её включил.
        val shareSettings = core.share.current().also { r -> r.diagnostics.forEach(core.log::diagnostic) }.valueOrNull()
        val share = if (shareSettings?.enabled == true) shareSettings.spec(tetherForConnect()) else null
        val job = currentCoroutineContext().job
        val report = try {
            val tun = handle.toTunInput().let { base ->
                // Сокеты ядра — в сеть устройства раздачи: с Bluetooth- и USB-модема путь к нему не по умолчанию.
                if (target == null) base else base.copy(protector = SocketProtector { fd -> base.protector.protect(fd) && RelayNetworks.bind(target.network, fd) })
            }
            if (relay != null && target != null) {
                core.connectVia(relay, target.address, checker, tun, share) { delay(it) }
            } else {
                core.connect(null, checker, tun, preferred, share) { delay(it) }
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
                    // Вопрос был о другом сервере (пользователь выбрал сам, подключение через устройство) — снят.
                    TunnelState.offer.value?.takeIf { it.fromId != report.profileId }?.let { ServerSwitch.clear(this@DPpassVpnService) }
                    val name = ir.profiles.firstOrNull { it.id == report.profileId }?.name ?: report.profileId.value
                    progress(TunnelStatus.Connected(report.profileId, name, core.clock.nowMillis(), Clock.MONOTONIC.nowMillis()))
                    watchNetwork(target?.network)
                    startTicker(report.session)
                    startSupervisor(core, graph.engine, ir, report.profileId)
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
     * Счётчики ядра → скорость и итоги (D-40). Раз в секунду, пока экран
     * включён; уведомление — реже: каждое обновление стоит батареи.
     */
    private fun startTicker(session: EngineSession) {
        ticker?.cancel()
        ticker = scope.launch {
            val meter = TrafficMeter()
            val power = getSystemService(PowerManager::class.java)
            var tick = 0
            while (isActive) {
                if (power.isInteractive) {
                    val traffic = meter.sample(session.stats(), Clock.MONOTONIC.nowMillis())
                    TunnelState.traffic(traffic)
                    if (tick % NOTIFY_EVERY == 0) (TunnelState.status.value as? TunnelStatus.Connected)?.let { startInForeground(it, traffic) }
                    tick++
                } else {
                    // Экран выключен: никто не смотрит — отсчёт скорости заново после включения.
                    meter.reset()
                }
                delay(1_000)
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
     */
    private fun startSupervisor(core: com.dpsmpx.dppass.connection.DPpassCore, engine: com.dpsmpx.dppass.engine.xray.XrayProxyEngine, ir: com.dpsmpx.dppass.config.ConfigIr, profileId: com.dpsmpx.dppass.core.ProfileId) {
        supervisor?.cancel()
        supervisor = scope.launch {
            val sup = core.supervisor(profileId, null)
            val profile = ir.profiles.firstOrNull { it.id == profileId }
            val probeTimeout = (core.policy.healthTimeoutMillis - PROBE_MARGIN_MILLIS).toInt()
            var samples = 0
            var lastFailure: Diagnostic? = null
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
                val stalled = failed && (result as Outcome.Failure).errors.any { it.code == DiagCode.PAYLOAD_STALLED }
                val decision = sup.onObservation(
                    StabilityObservation(success = !failed, rttMillis = elapsed, stalled = stalled, timestampMillis = core.clock.nowMillis()),
                    profile,
                    null,
                )
                if (failed) {
                    lastFailure = (result as Outcome.Failure).errors.first()
                    core.log.warning("adaptive_probe_failed", "profile" to Safe(profileId.value), "elapsed_ms" to elapsed)
                }
                if (++samples % PERSIST_EVERY_SAMPLES == 0 || decision == SessionSupervisor.Decision.RECONNECT) {
                    withContext(NonCancellable) { core.persistStability() }
                }
                if (decision == SessionSupervisor.Decision.RECONNECT) {
                    core.log.warning("adaptive_reconnect", "profile" to Safe(profileId.value))
                    // Деградация подтверждена и скачком задержки, без проваленной пробы — общая причина.
                    val reason = lastFailure ?: Diagnostic.error(DiagCode.HEALTH_CHECK_FAILED, "пробы через сервер раз за разом отвечают с перебоями")
                    onDegraded(core, profileId, reason)
                    reconnect(this@DPpassVpnService)
                    return@launch
                }
            }
        }
    }

    /**
     * Сбой сервера сессии (D-58): спросить о замене выбранного, заменить его
     * с согласием заранее или просто переподключиться по плану.
     */
    private fun onDegraded(core: DPpassCore, profileId: ProfileId, reason: Diagnostic) {
        val prefs = AppPrefs(this)
        when (val d = core.degraded(profileId, reason, prefs.selectedServer, prefs.autoSwitch, synchronized(declined) { declined.toSet() })) {
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
     * Сеть под туннелем — сеть по умолчанию (D-40): её тип и тарификацию видят
     * система и приложения. Через устройство раздачи (D-55) — его сеть
     * [fixed]: туннель идёт по ней, какая бы ни была сеть по умолчанию.
     */
    private fun watchNetwork(fixed: Network? = null) {
        if (fixed != null) {
            setUnderlyingNetworks(arrayOf(fixed))
            DeviceLog.log.info("underlying_network", "state" to Safe("relay"))
            return
        }
        val cm = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                setUnderlyingNetworks(arrayOf(network))
                DeviceLog.log.info("underlying_network", "state" to Safe("available"))
            }

            override fun onLost(network: Network) {
                setUnderlyingNetworks(null)
                DeviceLog.log.info("underlying_network", "state" to Safe("lost"))
            }
        }
        try {
            cm.registerDefaultNetworkCallback(callback)
            networkCallback = callback
        } catch (e: RuntimeException) {
            // Слишком много колбэков у процесса или нет разрешения — туннель работает и без этого.
            DeviceLog.log.diagnostic(Diagnostic.fromThrowable(DiagCode.INTERNAL_ERROR, "сеть под туннелем не отслеживается", e))
        }
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

    /** Ядро — потом TUN; повторный вызов ничего не делает. */
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
            connecting?.cancel()
            connecting = null
            session?.stop()
            session = null
            tunnel?.close()
            tunnel = null
        }
        // Опыт адаптивной модели — на диск, чтобы пережил остановку (D-44).
        withContext(NonCancellable) { AppGraph.graph(this@DPpassVpnService).core.persistStability() }
    }

    override fun onRevoke() {
        // Пользователь отозвал разрешение или включил другой VPN.
        DeviceLog.log.info("service_revoked")
        scope.launch {
            shutdown()
            TunnelState.set(TunnelStatus.Idle)
            announce()
            stopSelf()
        }
    }

    override fun onDestroy() {
        // Сервис уходит: уборка — в области процесса, она переживёт этот объект.
        AppGraph.scope.launch { shutdown() }
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

        /** Уведомление со скоростью — раз в столько секунд (только при включённом экране). */
        private const val NOTIFY_EVERY = 2

        /** Наблюдатель сессии (D-44): период пробы здоровья и как часто сохранять модель. */
        private const val SUPERVISION_INTERVAL_MILLIS = 15_000L
        private const val PERSIST_EVERY_SAMPLES = 8

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
