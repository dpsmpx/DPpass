package com.dpsmpx.dppass.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.dpsmpx.dppass.connection.RegimeMemory
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.engine.xray.SpeedReport
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine
import com.dpsmpx.dppass.network.Cooldown
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.ProbeNetwork
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbePlan
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.Prober
import com.dpsmpx.dppass.network.QuietWindow
import com.dpsmpx.dppass.network.SocketProber
import com.dpsmpx.dppass.network.UnderlyingNetworks
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Проверка сети по кнопке (D-60) и после смены сети при поднятом туннеле
 * (D-67): пробы [SocketProber] в сети под туннелем, бюджет D-14 — один на
 * процесс, проверка — одна за раз, итог — на экран и в журнал без адресов.
 * В план итог идёт только через память режима (D-64).
 */
object NetworkCheck {
    /** Кто начал проверку — в журнал (`network_check`), без адресов. */
    enum class Trigger { BUTTON, NETWORK_CHANGE }

    /** Идёт проверка: по кнопке и после смены сети — не вперемешку, пробы двух проверок упёрлись бы в бюджет. */
    private val checking = AtomicBoolean(false)

    /** Идёт проверка — своя или после смены сети. */
    fun busy(): Boolean = checking.get()

    /** Один на процесс: две проверки подряд упираются в предел, а не дают залп (D-14). */
    private val budget = ProbeBudget(Clock.MONOTONIC)

    /**
     * Через сколько мс полная проверка уложится в бюджет (0 — сейчас):
     * повтор раньше дал бы пропуски, а не вывод (D-60, 17.10.2026).
     */
    fun readyInMillis(): Long = budget.waitForMillis(ProbePlan.STANDARD.size)

    /** Идёт замер через туннель (D-61): один за раз. */
    private val measuring = AtomicBoolean(false)

    /**
     * Замер скорости и проверка сети — и [QUIET_AFTER_MILLIS] после них:
     * наблюдатель сессии (D-44) пробы не начинает, а начатую — не учитывает.
     * Нагрузка замера не должна выглядеть деградацией сервера (T14).
     */
    private val quiet = QuietWindow(Clock.MONOTONIC, QUIET_AFTER_MILLIS)

    /** Проба наблюдателя сейчас мерила бы свой замер, а не сервер. */
    fun probesQuiet(): Boolean = quiet.active()

    /**
     * Окно после замера: очередь в канале после загрузки и свои пробы
     * проверки — секунды. 17 октября 2026 проба, начатая через 0,4 и 2,4 с
     * после замера, во время проверки, проваливалась; между замерами —
     * проходила.
     */
    const val QUIET_AFTER_MILLIS: Long = 15_000

    /**
     * Пауза после замера (D-61): одна на процесс — уход с экрана её не
     * сбрасывает. После удачного замера — [SPEED_COOLDOWN_MILLIS] (25 МБ
     * трафика и нагрузка на сервер), после отказа — короче
     * ([SPEED_RETRY_MILLIS]): пользователь может сменить сервер и повторить.
     */
    private val speedCooldown = Cooldown(Clock.MONOTONIC)

    /** Через сколько мс можно мерить скорость снова (0 — сейчас). */
    fun speedReadyInMillis(): Long = speedCooldown.remainingMillis()

    /**
     * Пинг, jitter и скорость через туннель (D-61) — через сервер [profile]
     * поднятой сессии. Один замер за раз; null — замер уже идёт или пауза
     * после прошлого ещё не прошла ([speedReadyInMillis]).
     */
    suspend fun speed(engine: XrayProxyEngine, log: Logger, profile: ProfileId?): Outcome<SpeedReport>? {
        if (speedCooldown.remainingMillis() > 0 || !measuring.compareAndSet(false, true)) return null
        quiet.begin()
        var r: Outcome<SpeedReport>? = null
        return try {
            r = withContext(Dispatchers.IO) { engine.speedTest() }
            when (r) {
                is Outcome.Success -> with(r.value) {
                    log.info(
                        "speed_test",
                        "profile" to Safe(profile?.value ?: "?"),
                        "ping_ms" to Math.round(pingMillis),
                        "jitter_ms" to Math.round(jitterMillis),
                        "kbps" to downloadBitsPerSecond / 1000,
                        "bytes" to receivedBytes,
                        "ms" to transferMillis,
                        "stalled_ms" to stalledAfterMillis,
                        "active_kbps" to activeBitsPerSecond / 1000,
                    )
                }
                is Outcome.Failure -> r.errors.forEach(log::diagnostic)
            }
            r
        } finally {
            // Прерванный замер (ушли с экрана) — тоже трафик: пауза как после удачного.
            speedCooldown.restart(if (r is Outcome.Failure) SPEED_RETRY_MILLIS else SPEED_COOLDOWN_MILLIS)
            quiet.end()
            measuring.set(false)
        }
    }

    const val SPEED_COOLDOWN_MILLIS: Long = 60_000
    const val SPEED_RETRY_MILLIS: Long = 15_000

    /**
     * Режим сети по свежей проверке (D-64): одна память на процесс. В план
     * идёт только белый список — мягко, порядком, без исключений.
     */
    private val regime = RegimeMemory(Clock.MONOTONIC)

    /** Белый список по свежей проверке в нынешней сети под туннелем; null — режим неизвестен. */
    fun regime(context: Context): NetworkAssessment? = regime.allowlist(underlying(context).network?.networkHandle)

    /** Сколько мс назад была проверка, итог которой помнится; null — не помнится. */
    fun regimeAgeMillis(): Long? = regime.ageMillis()

    /** Опровергнут (подключился сервер, который под списком отказывал): режим снова неизвестен. */
    fun forgetRegime() = regime.forget()

    /** Сеть под туннелем (D-40, D-67): не VPN, с доступом в интернет; её меряет проверка. */
    internal class Underlying(val network: Network?, val type: NetworkType, val caps: NetworkCapabilities?)

    /** Проверить сеть; null — уже идёт другая проверка (D-67): её итог и будет итогом. */
    suspend fun run(
        context: Context,
        log: Logger,
        trigger: Trigger = Trigger.BUTTON,
        onResult: (ProbeResult) -> Unit = {},
    ): NetworkAssessment? = withContext(Dispatchers.IO) {
        if (!checking.compareAndSet(false, true)) return@withContext null
        quiet.begin()
        try {
            assess(context, log, trigger, onResult)
        } finally {
            quiet.end()
            checking.set(false)
        }
    }

    private suspend fun assess(context: Context, log: Logger, trigger: Trigger, onResult: (ProbeResult) -> Unit): NetworkAssessment {
        val u = underlying(context)
        val network = u.network
        val prober = if (network == null) {
            Prober { ProbeResult(it, ProbeOutcome.UNREACHABLE) }
        } else {
            SocketProber(AndroidProbeNetwork(network, u.caps), Clock.MONOTONIC, SecureRandom())
        }
        log.info("network_check", "type" to u.type, "trigger" to trigger)
        val assessment = NetworkAssessor(prober, budget) { delay(it) }.assess(u.type) { r ->
            log.info("network_probe", "kind" to r.request.kind, "target" to r.request.target, "outcome" to r.outcome, "ms" to r.latencyMillis)
            onResult(r)
        }
        log.info("network_assessed", "type" to assessment.type, "class" to assessment.restriction, "confidence" to assessment.confidence)
        // Итог — в память режима этой сети (D-64), любой: «не белый список» тоже сведение. Сеть в журнал не идёт.
        network?.let { regime.remember(assessment, it.networkHandle) }
        // Доводы классификатора — шаблоны без адресов и имён (NetworkClassifier).
        assessment.evidence.forEach { log.info("network_evidence", "text" to Safe(it)) }
        return assessment
    }

    /**
     * Сеть под туннелем сейчас — выбор [UnderlyingNetworks.pick] по снимку
     * сетей системы: сеть по умолчанию процесса, если она не VPN, иначе лучшая
     * из сетей без VPN. Ею пользуются и проверка, и память режима (D-64), и
     * сервис туннеля (D-40, D-67): ключи сети у них одни.
     */
    internal fun underlying(context: Context): Underlying {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return Underlying(null, NetworkType.NONE, null)
        val active = cm.activeNetwork

        @Suppress("DEPRECATION") // замена — NetworkCallback; здесь нужен снимок всех сетей сейчас, а не подписка
        val all = cm.allNetworks.toList()
        val caps = (listOfNotNull(active) + all).associateWith { cm.getNetworkCapabilities(it) }
        fun candidate(n: Network): UnderlyingNetworks.Candidate? = caps[n]?.let {
            UnderlyingNetworks.Candidate(
                n.networkHandle,
                type(it),
                vpn = it.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                internet = it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET),
                validated = it.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
            )
        }
        val chosen = UnderlyingNetworks.pick(active?.let(::candidate), all.mapNotNull(::candidate))
        val network = chosen?.let { c -> caps.keys.firstOrNull { it.networkHandle == c.handle } }
        return Underlying(network, chosen?.type ?: NetworkType.NONE, network?.let(caps::get))
    }

    private fun type(caps: NetworkCapabilities): NetworkType = when {
        caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
        caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
        caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
        else -> NetworkType.OTHER
    }

    /**
     * Пробы в сети [network]: её резолвер (с «Частным DNS», если он включён)
     * и сокеты, привязанные к ней; о странице входа говорит система.
     */
    private class AndroidProbeNetwork(private val network: Network, private val caps: NetworkCapabilities?) : ProbeNetwork {
        override fun resolve(host: String): List<InetAddress> = network.getAllByName(host).toList()

        override fun tcpSocket(): Socket = network.socketFactory.createSocket()

        override fun udpSocket(): DatagramSocket = DatagramSocket().also(network::bindSocket)

        override fun captivePortal(): Boolean? = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
    }
}
