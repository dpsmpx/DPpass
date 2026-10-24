package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.network.NetworkType
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.UnknownHostException
import java.nio.channels.SocketChannel
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Пробы проверки сети на ПК (D-79): метка до соединения, без метки — отказ, а не туннель. */
class LinuxProbeNetworkTest {
    private val none: (String) -> List<InetAddress> = { throw UnknownHostException(it) }

    @Test
    fun fdOfJdkChannelIsReadable() {
        SocketChannel.open().use { ch ->
            val fd = assertNotNull(LinuxProbeNetwork.fdOf(ch), "нужен флаг --add-exports java.base/sun.nio.ch (desktop/build.gradle.kts)")
            assertTrue(fd > 2)
        }
    }

    @Test
    fun socketsAreMarkedBeforeConnecting() {
        val marked = mutableListOf<Int>()
        val net = LinuxProbeNetwork({ fd -> marked += fd; 0 }, none)
        net.tcpSocket().use { assertFalse(it.isClosed) }
        net.udpSocket().use { assertFalse(it.isClosed) }
        assertEquals(2, marked.size)
        assertNull(net.ready())
    }

    @Test
    fun unmarkedSocketRefusesInsteadOfGoingIntoTheTunnel() {
        // Без CAP_NET_ADMIN SO_MARK отвечает EPERM (1).
        val net = LinuxProbeNetwork({ -1 }, none)
        val s = net.tcpSocket()
        assertTrue(s.isClosed, "сокет без метки закрыт")
        // Отказ соединения — IOException: проба считает его исходом, а не падает.
        assertFailsWith<IOException> { s.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), 9), 100) }
        assertTrue(net.udpSocket().isClosed)
        val why = assertNotNull(net.ready())
        assertEquals(DiagCode.NETWORK_CHECK_UNAVAILABLE, why.code)
        assertTrue("errno 1" in why.message, why.message)
    }

    @Test
    fun withoutNetAdminNoMarkIsNeeded() {
        // Без CAP_NET_ADMIN туннеля нет: сокеты и так идут мимо него.
        val net = LinuxProbeNetwork(null, none)
        net.tcpSocket().use { assertFalse(it.isClosed) }
        assertNull(net.ready())
    }

    @Test
    fun bridgeResolveReply() {
        val ok = byteArrayOf(0) + "192.0.2.10\n2001:db8::10".toByteArray()
        assertEquals(listOf("192.0.2.10", "2001:db8::10"), LinuxProbeNetwork.parseResolve("a.example", ok).map { IpAddress.of(it.address).toString() })
        assertFailsWith<UnknownHostException>("не адрес — отказ, а не резолв") {
            LinuxProbeNetwork.parseResolve("a.example", byteArrayOf(0) + "a.example".toByteArray())
        }
        val fail = byteArrayOf(2) + "lookup a.example: no such host".toByteArray()
        val e = assertFailsWith<UnknownHostException> { LinuxProbeNetwork.parseResolve("a.example", fail) }
        assertTrue("no such host" in e.message.orEmpty())
        assertFailsWith<UnknownHostException> { LinuxProbeNetwork.parseResolve("a.example", ByteArray(0)) }
    }

    @Test
    fun defaultRouteWithLowestMetricAndItsType() {
        val route = """
            Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
            enp3s0	00000000	0101A8C0	0003	0	0	100	00000000	0	0	0
            enp3s0	0001A8C0	00000000	0001	0	0	100	00FFFFFF	0	0	0
            wlan0	00000000	0102A8C0	0003	0	0	600	00000000	0	0	0
        """.trimIndent()
        val n = assertNotNull(LinuxNetwork.parse(route) { it == "wlan0" })
        assertEquals("enp3s0", n.iface)
        assertEquals(NetworkType.ETHERNET, n.type)
        val wifi = assertNotNull(LinuxNetwork.parse(route.lines().filterNot { it.startsWith("enp3s0") }.joinToString("\n")) { it == "wlan0" })
        assertEquals(NetworkType.WIFI, wifi.type)
        assertNotEquals(n.key, wifi.key, "другая сеть — другой ключ памяти режима")
        assertNull(LinuxNetwork.parse(route.lines().take(1).joinToString("\n")) { false }, "без маршрута по умолчанию — сети нет")
        assertEquals(NetworkType.MOBILE, LinuxNetwork.type("wwan0", false))
        assertEquals(NetworkType.OTHER, LinuxNetwork.type("usb0", false))
    }
}
