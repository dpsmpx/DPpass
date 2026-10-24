package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayDevice
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Устройство раздачи с ПК (D-85): шлюзы сетей ПК, вход SOCKS5 с паролем, сокеты — только из фабрики (мимо туннеля). */
class LinuxRelayNetworksTest {
    /** `/proc/net/route`: Wi-Fi телефона, USB-модем, публичный шлюз и маршрут не по умолчанию. */
    private var route = """
        Iface	Destination	Gateway 	Flags	RefCnt	Use	Metric	Mask		MTU	Window	IRTT
        wlp2s0	00000000	012BA8C0	0003	0	0	600	00000000	0	0	0
        wlp2s0	002BA8C0	00000000	0001	0	0	600	00FFFFFF	0	0	0
        enx0a	00000000	812AA8C0	0003	0	0	100	00000000	0	0	0
        enp3s0	00000000	017100CB	0003	0	0	50	00000000	0	0	0
    """.trimIndent()

    /** Что отвечает адрес: байты ответа входа; нет в карте — соединение отвергнуто. */
    private val replies = mutableMapOf<String, ByteArray>()
    private val dialed = mutableListOf<String>()

    private val sockets: () -> Socket = {
        object : Socket() {
            private var reply = ByteArray(0)

            override fun connect(endpoint: SocketAddress, timeout: Int) {
                val a = endpoint as InetSocketAddress
                val key = "${a.address.hostAddress}:${a.port}"
                dialed += key
                reply = replies[key] ?: throw ConnectException("отвергнуто: $key")
            }

            override fun getInputStream(): InputStream = ByteArrayInputStream(reply)

            override fun getOutputStream(): OutputStream = ByteArrayOutputStream()

            override fun setSoTimeout(timeout: Int) = Unit
        }
    }

    private val ifaces = listOf(
        LinuxShareInterfaces.Iface("wlp2s0", true, listOf(ip("192.168.43.20") to 24)),
        LinuxShareInterfaces.Iface("enx0a", true, listOf(ip("192.168.42.33") to 24)),
    )
    private val relays = LinuxRelayNetworks(
        sockets,
        { route },
        { i -> LinuxRelayNetworks.medium(i, wireless = i.startsWith("wl"), bus = if (i.startsWith("enx")) "usb" else "pci") },
        { ifaces },
    )

    private fun ip(s: String) = IpAddress.parse(s)!!

    private fun device(address: IpAddress? = null) =
        RelayDevice("d1", "Телефон", address, 41234, Secret("guest001"), Secret("synthetic-password-01"), 0)

    @Test
    fun gatewaysAreDefaultRoutesWithPrivateGateways() {
        val g = relays.gateways()
        assertEquals(listOf("192.168.43.1", "192.168.42.129"), g.map { it.address.toString() }, "публичный шлюз провода — не устройство раздачи")
        assertEquals(listOf(LinuxRelayNetworks.Medium.WIFI, LinuxRelayNetworks.Medium.USB), g.map { it.medium })
        route = "Iface\tDestination\n"
        assertTrue(relays.gateways().isEmpty())
    }

    @Test
    fun mediumByInterface() {
        assertEquals(LinuxRelayNetworks.Medium.WIFI, LinuxRelayNetworks.medium("wlan0", wireless = true, bus = "pci"))
        assertEquals(LinuxRelayNetworks.Medium.BLUETOOTH, LinuxRelayNetworks.medium("bnep0", wireless = false, bus = null))
        assertEquals(LinuxRelayNetworks.Medium.USB, LinuxRelayNetworks.medium("usb0", wireless = false, bus = "usb"))
        assertEquals(LinuxRelayNetworks.Medium.WIRED, LinuxRelayNetworks.medium("enp3s0", wireless = false, bus = "pci"))
    }

    @Test
    fun deviceIsFoundWhereItAcceptsLoginAndPassword() {
        replies["192.168.43.1:41234"] = byteArrayOf(5, 2) // вход без нашего пароля — не тот
        replies["192.168.42.129:41234"] = byteArrayOf(5, 2, 1, 0)
        val t = assertIs<Outcome.Success<LinuxRelayNetworks.Target>>(relays.locate(device())).value
        assertEquals(LinuxRelayNetworks.Target(LinuxRelayNetworks.Medium.USB, ip("192.168.42.129")), t)
        assertEquals(listOf("192.168.43.1:41234", "192.168.42.129:41234"), dialed, "только шлюзы, только сокетами фабрики")
    }

    @Test
    fun wrongPasswordAndSilenceHaveTheirOwnReasons() {
        replies["192.168.43.1:41234"] = byteArrayOf(5, 2, 1, 1)
        assertEquals(DiagCode.AUTHENTICATION_FAILED, assertIs<Outcome.Failure>(relays.locate(device())).errors.single().code)
        replies.clear()
        assertEquals(DiagCode.RELAY_NOT_FOUND, assertIs<Outcome.Failure>(relays.locate(device())).errors.single().code)
        route = ""
        val none = assertIs<Outcome.Failure>(relays.locate(device())).errors.single()
        assertEquals(DiagCode.RELAY_NOT_FOUND, none.code)
        assertTrue("ПК не подключён" in none.message)
    }

    @Test
    fun explicitAddressOnlyInsideASubnetOfThePc() {
        replies["192.168.43.7:41234"] = byteArrayOf(5, 2, 1, 0)
        val t = assertIs<Outcome.Success<LinuxRelayNetworks.Target>>(relays.locate(device(ip("192.168.43.7")))).value
        assertEquals(LinuxRelayNetworks.Medium.WIFI, t.medium)
        assertEquals(listOf("192.168.43.7:41234"), dialed, "шлюзы не спрашиваются")
        dialed.clear()
        assertIs<Outcome.Failure>(relays.locate(device(ip("10.9.9.9"))))
        assertTrue(dialed.isEmpty(), "адрес вне сетей ПК — не через чужой шлюз")
    }

    @Test
    fun pairingHostIsTheFirstGatewayThatListens() {
        assertNull(relays.pairingHost(), "никто не ждёт")
        replies["192.168.42.129:${Pairing.PORT}"] = ByteArray(0)
        assertNotNull(relays.pairingHost())
        assertEquals("192.168.42.129:${Pairing.PORT}", dialed.last())
    }

    @Test
    fun gatewayBytesFollowTheKernelOrder() {
        val g = LinuxRelayNetworks.parseGateways("h\nusb0\t00000000\t0101A8C0\t3\t0\t0\t0\t00000000\n")
        assertEquals(listOf("usb0" to ip("192.168.1.1")), g)
        assertTrue(LinuxRelayNetworks.parseGateways("h\nusb0\t00000000\t00000000\t1\t0\t0\t0\t00000000\n").isEmpty(), "без шлюза")
        assertTrue(LinuxRelayNetworks.parseGateways("h\nusb0\t00000000\tzz\t1\t0\t0\t0\t00000000\n").isEmpty(), "не число")
    }
}
