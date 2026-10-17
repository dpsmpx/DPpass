package com.dpsmpx.dppass.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.os.ParcelFileDescriptor
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.connection.Socks5Login
import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import java.io.IOException
import java.net.Inet4Address
import java.net.InetAddress
import java.net.InetSocketAddress

/**
 * Где искать устройство раздачи (D-55). Устройство раздачи — шлюз сети,
 * через которую этот телефон к нему подключён: его точки доступа Wi-Fi,
 * Bluetooth-модема или USB-модема (Android раздаёт подсеть с собой во
 * главе). Ничего не объявляется и не рассылается: телефон спрашивает шлюз
 * своей сети по протоколу входа раздачи — SOCKS5 с паролем (RFC 1929), и
 * ответит только вход, который знает этот логин и пароль.
 *
 * Сокеты — привязанные к сети ([Network.getSocketFactory]): сам DPpass
 * идёт мимо своего туннеля, а с Bluetooth- и USB-модема путь к шлюзу не
 * лежит через сеть по умолчанию.
 */
object RelayNetworks {
    enum class Medium { WIFI, BLUETOOTH, USB }

    /** Шлюз IPv4 сети телефона в частных адресах — возможное устройство раздачи. */
    data class Gateway(val network: Network, val medium: Medium, val address: IpAddress)

    /** Где ответило устройство: сеть, по которой к нему идти, и адрес. */
    data class Target(val network: Network, val medium: Medium, val address: IpAddress)

    private const val CONNECT_TIMEOUT_MILLIS = 1_500
    private const val READ_TIMEOUT_MILLIS = 1_500

    /** Шлюзы сетей Wi-Fi, Bluetooth и Ethernet/USB (не VPN) — снимок на сейчас. */
    fun gateways(context: Context): List<Gateway> = links(context).flatMap { (network, medium, props) ->
        props.routes.filter { it.isDefaultRoute }
            .mapNotNull { (it.gateway as? Inet4Address)?.let { gw -> IpAddress.of(gw.address) } }
            .filter(Cidr::isPrivateV4)
            .distinct()
            .map { Gateway(network, medium, it) }
    }

    /**
     * Найти устройство: по его явному адресу — в сети, в подсеть которой он
     * входит; без адреса — среди шлюзов. Первый вход, принявший логин и
     * пароль, — ответ. Блокирует поток: до двух коротких соединений на сеть.
     */
    fun locate(context: Context, device: RelayDevice): Outcome<Target> {
        val candidates = device.address?.let { at ->
            links(context).filter { (_, _, props) ->
                props.linkAddresses.any { la ->
                    val own = (la.address as? Inet4Address)?.let { IpAddress.of(it.address) }
                    own != null && at in Cidr.of(own, la.prefixLength)
                }
            }.map { (network, medium, _) -> Target(network, medium, at) }
        } ?: gateways(context).map { Target(it.network, it.medium, it.address) }
        if (candidates.isEmpty()) {
            return Outcome.failure(
                DiagCode.RELAY_NOT_FOUND,
                "телефон не подключён к устройству раздачи: подключитесь к его точке доступа Wi-Fi, Bluetooth- или USB-модему",
            )
        }
        var rejected = false
        for (c in candidates) {
            when (check(c.network, c.address, device)) {
                Socks5Login.Result.ACCEPTED -> return Outcome.Success(c)
                Socks5Login.Result.REJECTED -> rejected = true
                Socks5Login.Result.NOT_SOCKS, null -> Unit
            }
        }
        return if (rejected) {
            Outcome.failure(
                DiagCode.AUTHENTICATION_FAILED,
                "устройство раздачи не приняло логин и пароль: на нём их сменили («Новые логин, пароль и порт») — добавьте устройство заново",
            )
        } else {
            Outcome.failure(
                DiagCode.RELAY_NOT_FOUND,
                "устройство раздачи не ответило: на нём выключена «Раздача туннеля» или DPpass не подключён, либо сменился порт",
            )
        }
    }

    /** Вход раздачи [device] по [address] в сети [network]; null — не ответил вовсе. */
    fun check(network: Network, address: IpAddress, device: RelayDevice): Socks5Login.Result? = try {
        network.socketFactory.createSocket().use { s ->
            // Адрес из байтов — без DNS: getByAddress имён не резолвит.
            s.connect(InetSocketAddress(InetAddress.getByAddress(address.toBytes()), device.port), CONNECT_TIMEOUT_MILLIS)
            s.soTimeout = READ_TIMEOUT_MILLIS
            Socks5Login.check(s.getInputStream(), s.getOutputStream(), device.user, device.password)
        }
    } catch (e: IOException) {
        null
    }

    /**
     * Сокет ядра — в сеть устройства раздачи (D-55): с Bluetooth- и
     * USB-модема путь к шлюзу не идёт по сети по умолчанию. Хук ядра
     * вызывается до connect и bind — как раз когда привязка ещё возможна.
     */
    fun bind(network: Network, fd: Int): Boolean = try {
        ParcelFileDescriptor.fromFd(fd).use { network.bindSocket(it.fileDescriptor) }
        true
    } catch (e: IOException) {
        false
    }

    private fun links(context: Context): List<Triple<Network, Medium, android.net.LinkProperties>> {
        val cm = context.getSystemService(ConnectivityManager::class.java) ?: return emptyList()
        @Suppress("DEPRECATION") // замена — NetworkCallback; здесь нужен снимок по нажатию, а не подписка
        val networks = cm.allNetworks
        return networks.mapNotNull { n ->
            val caps = cm.getNetworkCapabilities(n) ?: return@mapNotNull null
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return@mapNotNull null
            val medium = when {
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> Medium.WIFI
                caps.hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> Medium.BLUETOOTH
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> Medium.USB
                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && caps.hasTransport(NetworkCapabilities.TRANSPORT_USB) -> Medium.USB
                else -> return@mapNotNull null
            }
            val props = cm.getLinkProperties(n) ?: return@mapNotNull null
            Triple(n, medium, props)
        }
    }
}
