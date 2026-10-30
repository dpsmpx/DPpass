package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.HostAddress
import com.dpsmpx.dppass.engine.SystemTun
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeNetwork
import com.dpsmpx.dppass.network.SystemProbeNetwork
import com.dpsmpx.dppass.storage.KeyWrapper
import com.dpsmpx.dppass.tunnel.PlatformTraits
import com.dpsmpx.dppass.tunnel.TunnelSpec

/**
 * Windows (D-97): права администратора (UAC), сеть — маршрут по умолчанию
 * мимо адаптера DPpass от моста ([WindowsNative.nativeDefaultRoute]): по
 * нему видна и смена сети под туннелем (D-80). Проверка сети — только без
 * туннеля ([WindowsProbeNetwork]).
 */
class WindowsHost(
    /** Ответ моста о маршруте по умолчанию; null — библиотеки ядра нет. */
    private val route: (() -> ByteArray)?,
    private val elevated: () -> Boolean,
) : DesktopHost {
    override val id: String = "windows"

    override fun tunnelAllowed(): Boolean = elevated()

    override val tunnelRefusal: String =
        "DPpass запущен без прав администратора — туннель (VPN) не поднять: адаптер Wintun создаёт только администратор. " +
            "Запустите его через dppass.exe: Windows спросит разрешение (D-97). " +
            "Или подключитесь без VPN: прокси для программ, где его можно указать (D-95)."

    override fun network(): DesktopNetwork? = route?.let { parseRoute(it()).network }

    /** Поднят ли адаптер DPpass: пока он есть, пробы ушли бы в туннель. */
    fun tunnelUp(): Boolean = route?.let { parseRoute(it()).tunUp } ?: false

    override val checksUnderTunnel: Boolean = false

    override val absent: String =
        "На Windows нет раздачи с ПК (D-84) и подключения через устройство раздачи (D-85) — вкладок для них здесь нет (D-97). " +
            "Проверка сети — только без туннеля: через туннель она мерила бы сервер, а не сеть."

    /** Ответ [WindowsNative.nativeDefaultRoute] — сеть и поднят ли адаптер. */
    data class Route(val network: WindowsNetwork?, val tunUp: Boolean)

    companion object {
        /** Признаки Windows для `TunnelSpec`: исключающих маршрутов у входа TUN ядра нет. */
        val TRAITS: PlatformTraits = PlatformTraits(supportsExcludeRoute = false)

        fun isWindows(osName: String = System.getProperty("os.name").orEmpty()): Boolean = osName.startsWith("Windows")

        /** Разбор ответа моста; не разобрано — сети нет (сеть только подсказывает режим, D-64). */
        fun parseRoute(reply: ByteArray): Route {
            if (reply.isEmpty() || reply[0].toInt() != 0) return Route(null, false)
            val lines = String(reply, 1, reply.size - 1, Charsets.UTF_8).lines()
            val up = lines.firstOrNull() == "1"
            val f = lines.getOrNull(1)?.split('\t')
            val net = if (f != null && f.size == 3) WindowsNetwork(f[0], f[1], kind(f[2])) else null
            return Route(net, up)
        }

        private fun kind(k: String): NetworkType = when (k) {
            "1" -> NetworkType.ETHERNET
            "2" -> NetworkType.WIFI
            "3" -> NetworkType.MOBILE
            else -> NetworkType.OTHER
        }
    }
}

/** Сеть Windows: псевдоним интерфейса и шлюз маршрута по умолчанию; ключ — как на Linux. */
data class WindowsNetwork(val alias: String, val gateway: String, override val type: NetworkType) : DesktopNetwork {
    override val key: Long get() = "$alias|$gateway".hashCode().toLong()
}

/**
 * Туннель Windows (D-97): адаптер Wintun создаёт вход TUN ядра. Здесь —
 * только описание адаптера по [TunnelSpec] ([SystemTun]); закрывать нечего:
 * адаптер уходит вместе с ядром. Раздачи на Windows нет, политика приложений
 * — только «все, кроме DPpass», как на Linux (D-05).
 */
class WindowsTunnels(private val selfPackage: String, private val log: Logger, private val elevated: () -> Boolean) : DesktopTunnels {
    override fun establish(spec: TunnelSpec, share: List<Cidr>): Outcome<DesktopTunnel> {
        if (!elevated()) {
            return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "нет прав администратора — адаптер Wintun не создать; запустите DPpass через dppass.exe")
        }
        if (share.isNotEmpty()) return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "раздачи на Windows нет (D-97)")
        LinuxRoutes.appPolicyProblem(spec, selfPackage, system = "Windows")?.let { return Outcome.failure(it) }
        val system = when (val s = systemTun(spec)) {
            is Outcome.Failure -> return s
            is Outcome.Success -> s.value
        }
        log.info("windows_tunnel", "routes" to system.routes.size, "addresses" to system.addresses.size)
        return Outcome.Success(Core(system))
    }

    private class Core(override val systemTun: SystemTun) : DesktopTunnel {
        override val tunInput: TunInput? = null

        override fun close() = Unit
    }

    companion object {
        /**
         * Адаптер по [TunnelSpec]: адрес — первый хост сети (`172.19.0.1/30`,
         * а не номер сети: Windows его не назначит); маршруты — как есть
         * (исключённое уже выпало дополнением, [WindowsHost.TRAITS]); DNS —
         * внутренний адрес.
         */
        fun systemTun(spec: TunnelSpec): Outcome<SystemTun> {
            if (spec.excludedRoutes.isNotEmpty()) {
                return Outcome.failure(DiagCode.TUN_ESTABLISH_FAILED, "исключающих маршрутов у адаптера ядра нет — TunnelSpec собран не для Windows")
            }
            val addresses = listOfNotNull(spec.address4, spec.address6).map { firstHost(it) }
            return Outcome.Success(SystemTun(addresses, spec.routes, spec.dnsServers))
        }

        /** Первый адрес хоста подсети: номер сети + 1 (у /30 и /126 биты хоста — нули). */
        fun firstHost(cidr: Cidr): HostAddress {
            val b = cidr.network.toBytes()
            b[b.size - 1] = (b[b.size - 1] + 1).toByte()
            return HostAddress(IpAddress.of(b), cidr.prefix)
        }
    }
}

/**
 * Ключ данных под DPAPI текущего пользователя Windows (D-97, D-19):
 * расшифровать его может только он на этом ПК. На Linux обёртки нет (D-74).
 * Потерян ключ, только когда мост говорит, что блок не открыть никогда
 * ([LOST]: испорчен, другого пользователя или ПК); прочий отказ DPAPI —
 * временный: повторить, а не сбрасывать данные.
 */
class DpapiKeyWrapper(
    private val protect: (ByteArray) -> ByteArray = WindowsNative::nativeProtect,
    private val unprotect: (ByteArray) -> ByteArray = WindowsNative::nativeUnprotect,
) : KeyWrapper {
    override fun exists(): Boolean = true

    override fun create() = Unit

    override fun wrap(plain: ByteArray): ByteArray {
        val reply = protect(plain)
        check(reply.isNotEmpty() && reply[0].toInt() == 0) { "DPAPI не зашифровал ключ данных: ${text(reply)}" }
        return reply.copyOfRange(1, reply.size)
    }

    override fun unwrap(sealed: ByteArray): ByteArray {
        val reply = unprotect(sealed)
        check(reply.isNotEmpty()) { "мост не ответил на DPAPI" }
        if (reply[0].toInt() == LOST) throw KeyWrapper.KeyLost("ключ данных под DPAPI не расшифровать: ${text(reply)}")
        check(reply[0].toInt() == 0) { "DPAPI сейчас не расшифровал ключ данных: ${text(reply)}" }
        return reply.copyOfRange(1, reply.size)
    }

    private fun text(reply: ByteArray): String = if (reply.isEmpty()) "мост не ответил" else String(reply, 1, reply.size - 1, Charsets.UTF_8)

    private companion object {
        /** Вид отказа моста `KindConfig` у `Unprotect`: блок не открыть никогда (`tools/xray/bridge/dpapi_windows.go`). */
        const val LOST = 1
    }
}

/**
 * Пробы проверки сети на Windows (D-79, D-97): сокеты системы — мимо
 * туннеля они идут, только пока адаптера DPpass нет. Пока туннель поднят,
 * проверка отказывает с причиной: через туннель она мерила бы сервер, а не
 * сеть (D-05). Вывести пробы из туннеля — следующей версией.
 */
class WindowsProbeNetwork(private val tunnelUp: () -> Boolean) : DesktopProbeNetwork, ProbeNetwork by SystemProbeNetwork {
    override fun ready(): Diagnostic? = if (!tunnelUp()) {
        null
    } else {
        Diagnostic.error(
            DiagCode.NETWORK_CHECK_UNAVAILABLE,
            "на Windows проверка сети — только без туннеля (D-97): отключитесь и проверьте; через туннель она мерила бы сервер, а не сеть",
        )
    }
}

/** Имя адаптера, который создаёт ядро: его пропускает маршрут по умолчанию. */
internal val WINDOWS_TUN_ALIAS: String = XrayBackend.TUN_NAME
