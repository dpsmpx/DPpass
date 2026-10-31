package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import java.net.ConnectException
import java.net.Socket
import java.net.SocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Устройство раздачи на Windows (D-102): сети ПК — от моста; под туннелем сокет поиска привязан к интерфейсу той сети. */
class WindowsRelayNetworksTest {
    private fun reply(status: Int, text: String): ByteArray = byteArrayOf(status.toByte()) + text.toByteArray(Charsets.UTF_8)

    private fun ip(s: String) = IpAddress.parse(s)!!

    /** Wi-Fi телефона, его USB-модем (RNDIS) и провод к роутеру без частного шлюза. */
    private val nets = reply(
        0,
        "2\t0\t\t192.0.2.50/24\tEthernet\n" +
            "3\t1\t192.168.43.1\t192.168.43.20/24\tWi-Fi\n" +
            "7\t2\t192.168.42.129\t192.168.42.33/24\tEthernet 3\n",
    )

    private var up = false
    private val binds = mutableListOf<Int>()
    private var bindReply = byteArrayOf(0)
    private val bind: (Long, Int) -> ByteArray = { _, index ->
        binds += index
        bindReply
    }

    /** Сокеты поиска — без сети: запоминают номер интерфейса и отказывают в соединении. */
    private val dialed = mutableListOf<Int>()
    private val relays = WindowsRelayNetworks.create({ nets }, { up }, bind) { index ->
        dialed += index
        object : Socket() {
            override fun connect(endpoint: SocketAddress, timeout: Int) = throw ConnectException("нет сети в тесте")
        }
    }

    @Test
    fun gatewaysAndInterfacesComeFromTheBridge() {
        assertEquals(
            listOf(
                RelayNetworks.Gateway("Wi-Fi", RelayNetworks.Medium.WIFI, ip("192.168.43.1"), 3),
                RelayNetworks.Gateway("Ethernet 3", RelayNetworks.Medium.USB, ip("192.168.42.129"), 7),
            ),
            relays.gateways(),
        )
        val parsed = WindowsRelayNetworks.parse(nets)!!
        assertEquals(listOf(2, 3, 7), parsed.map { it.index })
        assertEquals(listOf(ip("192.0.2.50") to 24), parsed.first().addresses)
    }

    @Test
    fun anyDoubtMeansNoNetworks() {
        assertNull(WindowsRelayNetworks.parse(reply(1, "GetIPForwardTable2: отказ")))
        assertNull(WindowsRelayNetworks.parse(ByteArray(0)))
        assertNull(WindowsRelayNetworks.parse(reply(0, "3\t1\t192.168.43.1\t192.168.43.20/24\n")), "без псевдонима")
        assertNull(WindowsRelayNetworks.parse(reply(0, "x\t1\t\t\tWi-Fi\n")), "номер не число")
        assertNull(WindowsRelayNetworks.parse(reply(0, "3\t9\t\t\tWi-Fi\n")), "вид вне договора")
        assertNull(WindowsRelayNetworks.parse(reply(0, "3\t1\t203.0.113.1\t\tWi-Fi\n")), "публичный шлюз — не телефон")
        assertNull(WindowsRelayNetworks.parse(reply(0, "3\t1\t\t192.168.43.20\tWi-Fi\n")), "адрес без префикса")
        assertEquals(emptyList(), WindowsRelayNetworks.parse(reply(0, "")))
        val none = WindowsRelayNetworks.create({ reply(1, "отказ") }, { false }, bind)
        assertTrue(none.gateways().isEmpty())
    }

    @Test
    fun aliasWithSpacesAndTabsLaterIsKeptWhole() {
        // Псевдоним — последнее поле: всё до конца строки, хоть с пробелами.
        val n = WindowsRelayNetworks.parse(reply(0, "7\t2\t192.168.42.129\t\tRemote NDIS сеть 2\n"))!!.single()
        assertEquals("Remote NDIS сеть 2", n.alias)
    }

    @Test
    fun eachGatewayIsAskedOverItsOwnInterface() {
        assertNull(relays.pairingHost(), "никто не ждёт")
        assertEquals(listOf(3, 7), dialed, "Wi-Fi телефона — интерфейс 3, USB-модем — 7")
    }

    @Test
    fun withoutTunnelSocketIsPlainUnderItBoundToTheNetwork() {
        WindowsRelayNetworks.socket(3, { false }, bind).use { s ->
            assertNull(s.channel, "туннеля нет — сокет системы")
            assertTrue(binds.isEmpty())
        }
        WindowsRelayNetworks.socket(7, { true }, bind).use { s ->
            assertEquals(listOf(7), binds, "под туннелем — привязка к интерфейсу сети")
            assertFalse(s.isClosed)
        }
    }

    @Test
    fun socketThatDidNotBindIsClosedNotSentIntoTheTunnel() {
        bindReply = byteArrayOf(4) + "IP_UNICAST_IF: отказ".toByteArray()
        assertTrue(WindowsRelayNetworks.socket(7, { true }, bind).isClosed, "не привязался — закрыт, а не путь в туннель")
        bindReply = byteArrayOf(0)
        assertTrue(WindowsRelayNetworks.socket(0, { true }, bind).isClosed, "номера интерфейса нет — привязать не к чему")
    }
}
