package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.Cidr
import com.dpsmpx.dppass.core.IpAddress
import java.net.Socket
import java.nio.channels.SocketChannel

/**
 * Сети ПК на Windows для устройства раздачи (D-102, к D-85): интерфейсы,
 * шлюзы и адреса — от моста ([WindowsNative.nativeRelayNetworks],
 * `tools/xray/bridge/relay_windows.go`). Пока туннель поднят, сокет поиска
 * до соединения привязывается к интерфейсу той сети (IP_UNICAST_IF, как
 * пробы D-99): иначе он мог бы уйти в туннель. Не привязался — сокет закрыт,
 * поиск по этой сети отказывает, а не идёт в туннель.
 */
object WindowsRelayNetworks {
    fun create(
        /** Ответ моста о сетях ПК; статус первым байтом. */
        reply: () -> ByteArray,
        tunnelUp: () -> Boolean,
        /** Привязка сокета к интерфейсу: ответ моста — статус ([WindowsNative.nativeBindSocket]). */
        bind: (Long, Int) -> ByteArray,
        /** Сокет поиска к интерфейсу с номером ([socket]); в тестах — без сети. */
        sockets: (Int) -> Socket = { index -> socket(index, tunnelUp, bind) },
    ): RelayNetworks = RelayNetworks(
        sockets,
        { parse(reply()).orEmpty().flatMap { n -> n.gateways.map { RelayNetworks.Gateway(n.alias, n.medium, it, n.index) } } },
        { parse(reply())?.map { RelayNetworks.Iface(it.alias, it.medium, up = true, it.addresses, it.index) } },
    )

    /** Интерфейс из ответа моста: номер, вид, частные шлюзы, адреса IPv4 и псевдоним. */
    data class Net(
        val index: Int,
        val medium: RelayNetworks.Medium,
        val gateways: List<IpAddress>,
        val addresses: List<Pair<IpAddress, Int>>,
        val alias: String,
    )

    /**
     * Ответ моста → интерфейсы; отказ или неразобранная строка — null: сетей
     * не узнать, и искать устройство негде. Шлюз не частный IPv4 — не
     * устройство раздачи, как на Linux.
     */
    fun parse(reply: ByteArray): List<Net>? {
        if (reply.isEmpty() || reply[0].toInt() != 0) return null
        return String(reply, 1, reply.size - 1, Charsets.UTF_8).lines().filter { it.isNotBlank() }.map { line ->
            val f = line.split('\t', limit = FIELDS)
            if (f.size != FIELDS || f[4].isBlank()) return null
            val index = f[0].toIntOrNull()?.takeIf { it > 0 } ?: return null
            val medium = f[1].toIntOrNull()?.let { MEDIA.getOrNull(it) } ?: return null
            val gateways = list(f[2]).map { IpAddress.parseV4(it)?.takeIf(Cidr::isPrivateV4) ?: return null }
            val addresses = list(f[3]).map { p ->
                val slash = p.indexOf('/')
                if (slash < 0) return null
                val ip = IpAddress.parseV4(p.substring(0, slash)) ?: return null
                val prefix = p.substring(slash + 1).toIntOrNull()?.takeIf { it in 1..IPV4_BITS } ?: return null
                ip to prefix
            }
            Net(index, medium, gateways, addresses, f[4])
        }
    }

    private fun list(field: String): List<String> = if (field.isEmpty()) emptyList() else field.split(',')

    /** Туннеля нет — сокет системы; есть — привязанный к интерфейсу [index], а не привязался — закрытый. */
    fun socket(index: Int, tunnelUp: () -> Boolean, bind: (Long, Int) -> ByteArray): Socket {
        if (!tunnelUp()) return Socket()
        val ch = SocketChannel.open()
        val handle = LinuxProbeNetwork.fdOf(ch)
        if (index <= 0 || handle == null || WindowsProbeNetwork.failure(bind(handle.toLong(), index)) != null) ch.close()
        return ch.socket()
    }

    /** Вид сети по числу моста: порядок — `RelayMedium` в `relay_windows.go`. */
    private val MEDIA = listOf(RelayNetworks.Medium.WIRED, RelayNetworks.Medium.WIFI, RelayNetworks.Medium.USB, RelayNetworks.Medium.BLUETOOTH)

    private const val FIELDS = 5
    private const val IPV4_BITS = 32
}
