package com.dpsmpx.dppass.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import com.dpsmpx.dppass.core.Clock
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Safe
import com.dpsmpx.dppass.network.NetworkAssessment
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.ProbeNetwork
import com.dpsmpx.dppass.network.ProbeOutcome
import com.dpsmpx.dppass.network.ProbeResult
import com.dpsmpx.dppass.network.Prober
import com.dpsmpx.dppass.network.SocketProber
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.withContext
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.security.SecureRandom

/**
 * Проверка сети по кнопке (D-60): пробы [SocketProber] в сети под
 * туннелем, бюджет D-14 — один на процесс, итог — на экран и в журнал
 * без адресов. В план подключения итог не идёт (D-60).
 */
object NetworkCheck {
    /** Один на процесс: две проверки подряд упираются в предел, а не дают залп (D-14). */
    private val budget = ProbeBudget(Clock.MONOTONIC)

    /** Сеть, которую меряет проверка: не VPN, с доступом в интернет. */
    private class Underlying(val network: Network?, val type: NetworkType, val caps: NetworkCapabilities?)

    suspend fun run(context: Context, log: Logger, onResult: (ProbeResult) -> Unit): NetworkAssessment = withContext(Dispatchers.IO) {
        val u = underlying(context)
        val network = u.network
        val prober = if (network == null) {
            Prober { ProbeResult(it, ProbeOutcome.UNREACHABLE) }
        } else {
            SocketProber(AndroidProbeNetwork(network, u.caps), Clock.MONOTONIC, SecureRandom())
        }
        log.info("network_check", "type" to u.type)
        val assessment = NetworkAssessor(prober, budget) { delay(it) }.assess(u.type) { r ->
            log.info("network_probe", "kind" to r.request.kind, "target" to r.request.target, "outcome" to r.outcome, "ms" to r.latencyMillis)
            onResult(r)
        }
        log.info("network_assessed", "type" to assessment.type, "class" to assessment.restriction, "confidence" to assessment.confidence)
        // Доводы классификатора — шаблоны без адресов и имён (NetworkClassifier).
        assessment.evidence.forEach { log.info("network_evidence", "text" to Safe(it)) }
        assessment
    }

    private fun underlying(context: Context): Underlying {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return Underlying(null, NetworkType.NONE, null)
        // Процесс DPpass — вне своего туннеля (D-17): его сеть по умолчанию — сеть под туннелем.
        @Suppress("DEPRECATION") // замена — NetworkCallback; здесь нужен снимок по нажатию, а не подписка
        val all = listOfNotNull(cm.activeNetwork) + cm.allNetworks
        val network = all.firstOrNull { n ->
            cm.getNetworkCapabilities(n)?.let { !it.hasTransport(NetworkCapabilities.TRANSPORT_VPN) && it.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) } == true
        }
        val caps = network?.let(cm::getNetworkCapabilities)
        val type = when {
            caps == null -> NetworkType.NONE
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> NetworkType.WIFI
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> NetworkType.MOBILE
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> NetworkType.ETHERNET
            else -> NetworkType.OTHER
        }
        return Underlying(network, type, caps)
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
