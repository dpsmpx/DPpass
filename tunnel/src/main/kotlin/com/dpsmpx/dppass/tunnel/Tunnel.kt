package com.dpsmpx.dppass.tunnel

import com.dpsmpx.dppass.config.ConfigIr
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.HostAddress
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.AppLowering
import com.dpsmpx.dppass.routing.AppPolicy

/**
 * Описание TUN, независимое от Android (D-17): что должен сделать
 * `VpnService.Builder`, но без него. Android-слой (`app/`) переводит
 * спецификацию в вызовы Builder один к одному и ничего не решает сам.
 */
data class TunnelSpec(
    /** Адрес TUN — узла, а не номер сети (`172.19.0.1/30`): так его получает интерфейс. */
    val address4: HostAddress,
    val address6: HostAddress?,
    /** Маршруты в туннель. */
    val routes: List<Cidr>,
    /** Исключённые маршруты (только если платформа умеет excludeRoute). */
    val excludedRoutes: List<Cidr>,
    val dnsServers: List<IpAddress>,
    val mtu: Int,
    /** Кто в туннеле; собственный пакет DPpass уже исключён. */
    val apps: AppPolicy,
    /**
     * IPv6 без маршрута в туннель шёл бы мимо него (утечка). Если IPv6
     * не туннелируется, он блокируется: маршрут `::/0` в туннель, где
     * ядро его отбрасывает.
     */
    val ipv6Mode: Ipv6Mode,
    val metered: Boolean = false,
)

enum class Ipv6Mode { TUNNELED, BLOCKED }

/** Что умеет платформа, на которой строится TUN. */
data class PlatformTraits(
    /** `Builder.excludeRoute` — Android 13 (API 33) и выше. */
    val supportsExcludeRoute: Boolean,
    val supportsIpv6: Boolean = true,
)

object TunnelSpecBuilder {
    val ADDRESS4: HostAddress = HostAddress.parse("172.19.0.1/30")!!
    val ADDRESS6: HostAddress = HostAddress.parse("fdfe:dcba:9876::1/126")!!

    /** Внутренний адрес DNS в туннеле: запросы к нему перехватывает ядро. */
    val TUN_DNS4: IpAddress = IpAddress.parse("172.19.0.2")!!

    /** Локальные сети, которые при bypassLan идут мимо туннеля. */
    val LAN: List<Cidr> = listOf(
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10",
        "fc00::/7", "fe80::/10",
    ).map { Cidr.parse(it)!!.cidr }

    const val DEFAULT_MTU: Int = 1500

    fun build(ir: ConfigIr, selfPackage: String, platform: PlatformTraits, mtu: Int = DEFAULT_MTU): Outcome<TunnelSpec> {
        val lowered = AppLowering.lower(ir.routing)
        val apps = withoutSelf(lowered.tunnelApps, selfPackage)
        // Пустой список «только этих» VpnService.Builder понимает как «все приложения» —
        // смысл перевернулся бы молча (D-05). Туннель не для кого — отказ.
        if (apps is AppPolicy.OnlyApps && apps.packages.isEmpty()) {
            return Outcome.failure(
                DiagCode.APP_POLICY_CONFLICT,
                "туннель только для выбранных приложений, а ни одного не выбрано",
                "$.routing.apps",
            )
        }

        val lan = if (ir.routing.bypassLan) LAN else emptyList()
        val (routes, excluded) = when {
            lan.isEmpty() -> listOf(Cidr.ALL_V4, Cidr.ALL_V6) to emptyList()
            platform.supportsExcludeRoute -> listOf(Cidr.ALL_V4, Cidr.ALL_V6) to lan
            else -> (Cidr.complement(Cidr.ALL_V4, lan) + Cidr.complement(Cidr.ALL_V6, lan)) to emptyList()
        }
        // Приложения в туннеле спрашивают DNS у внутреннего адреса; ядро перехватывает
        // запросы и отвечает по DnsPolicy (в том числе через «прямой» сервер, если так задано).
        val ipv6 = if (platform.supportsIpv6) Ipv6Mode.TUNNELED else Ipv6Mode.BLOCKED
        return Outcome.Success(TunnelSpec(ADDRESS4, ADDRESS6, routes, excluded, listOf(TUN_DNS4), mtu, apps, ipv6))
    }

    private fun withoutSelf(apps: AppPolicy, self: String): AppPolicy = when (apps) {
        AppPolicy.AllApps -> AppPolicy.ExceptApps(setOf(self))
        is AppPolicy.ExceptApps -> AppPolicy.ExceptApps(apps.packages + self)
        is AppPolicy.OnlyApps -> AppPolicy.OnlyApps(apps.packages - self)
    }
}

/** Поднятый TUN. [fd] — дескриптор от платформы; домен им не пользуется, только передаёт ядру. */
interface TunnelHandle {
    val fd: Int
    val spec: TunnelSpec

    /**
     * Вывести сокет из этого TUN (`VpnService.protect` на Android): так
     * соединения ядра к серверу не возвращаются в туннель петлёй (T4, D-25).
     * Ложь — не вышло; ядро такой сокет не использует.
     */
    fun protect(socketFd: Int): Boolean

    /** Закрыть TUN — после остановки ядра: fd принадлежит платформе (D-25). */
    fun close()
}

/** Платформа, умеющая поднять TUN по спецификации (Android — `VpnService`). */
interface TunnelProvider {
    suspend fun establish(spec: TunnelSpec): Outcome<TunnelHandle>
}

/** Для тестов и `cli`: запоминает спецификации, «поднимает» фиктивный fd. */
class FakeTunnelProvider(private val fail: Boolean = false) : TunnelProvider {
    val established: MutableList<TunnelSpec> = mutableListOf()
    var open: Int = 0
        private set

    /** Сокеты, выведенные из туннеля. */
    val protected: MutableList<Int> = mutableListOf()

    override suspend fun establish(spec: TunnelSpec): Outcome<TunnelHandle> {
        if (fail) return Outcome.failure(com.dpsmpx.dppass.diagnostics.DiagCode.TUN_ESTABLISH_FAILED, "fake: TUN не поднят по сценарию")
        established += spec
        open++
        return Outcome.Success(object : TunnelHandle {
            override val fd: Int = 100 + established.size
            override val spec: TunnelSpec = spec
            override fun protect(socketFd: Int): Boolean = protected.add(socketFd)
            override fun close() {
                open--
            }
        })
    }
}
