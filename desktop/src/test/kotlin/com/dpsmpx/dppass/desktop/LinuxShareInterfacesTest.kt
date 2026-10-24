package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.IpAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Точка доступа ПК (D-84): что раздаёт — говорит NetworkManager; сомнение — не раздавать. */
class LinuxShareInterfacesTest {
    private val hotspot = "00000000-0000-4000-8000-000000000001"
    private val wired = "00000000-0000-4000-8000-000000000002"
    private val calls = mutableListOf<List<String>>()
    private var active = CommandResult(0, "$hotspot:wlp2s0\n$wired:enp3s0\n")
    private val methods = mutableMapOf(hotspot to "shared", wired to "auto")

    private val nmcli: (List<String>) -> CommandResult = { args ->
        calls += args
        when {
            "--active" in args -> active
            else -> methods[args.last()]?.let { CommandResult(0, "$it\n") } ?: CommandResult(10, "Error: no such connection profile.")
        }
    }

    private var ifaces = listOf(
        LinuxShareInterfaces.Iface("wlp2s0", true, listOf(ip("10.42.0.1") to 24)),
        LinuxShareInterfaces.Iface("enp3s0", true, listOf(ip("192.168.1.20") to 24)),
        LinuxShareInterfaces.Iface("lo", false, listOf(ip("127.0.0.1") to 8)),
    )
    private var upstream: String? = "enp3s0"
    private val shares = LinuxShareInterfaces(nmcli, { ifaces }, { upstream })

    private fun ip(s: String) = IpAddress.parse(s)!!

    @Test
    fun onlySharedConnectionsOfNetworkManagerAreShared() {
        val scan = shares.find()
        assertEquals(LinuxShareInterfaces.Source.OK, scan.source)
        assertEquals(listOf("10.42.0.1/24"), scan.endpoints.map { it.toString() }, "провод к роутеру — чужая сеть, не раздача")
        assertEquals("nmcli=0 active=2 shared=1 endpoints=1", scan.seen)
        assertTrue(listOf("wlp2s0", "enp3s0", "10.42", "192.168").none { it in scan.seen }, "в журнал — без имён и адресов (D-57)")
        // Соединение — по UUID, а не по имени: имя могло бы совпасть с другим.
        assertEquals(listOf("--get-values", "ipv4.method", "connection", "show", "uuid", hotspot), calls[1])
    }

    @Test
    fun aSecondLanLooksLikeAHotspotButIsNotShared() {
        // Признаки те же — частный IPv4, широковещание, не маршрут по умолчанию; NetworkManager говорит «auto».
        ifaces = ifaces + LinuxShareInterfaces.Iface("enp4s0", true, listOf(ip("192.168.50.2") to 24))
        active = CommandResult(0, active.output + "00000000-0000-4000-8000-000000000003:enp4s0\n")
        methods["00000000-0000-4000-8000-000000000003"] = "manual"
        assertEquals(listOf("10.42.0.1/24"), shares.find().endpoints.map { it.toString() })
    }

    @Test
    fun upstreamIsNeverSharedWhateverNetworkManagerSays() {
        upstream = "wlp2s0"
        assertTrue(shares.find().endpoints.isEmpty())
    }

    @Test
    fun publicOrTooNarrowAddressIsNotAnEndpoint() {
        ifaces = listOf(LinuxShareInterfaces.Iface("wlp2s0", true, listOf(ip("203.0.113.1") to 24, ip("10.42.0.1") to 31)))
        assertTrue(shares.find().endpoints.isEmpty(), "вход только на частном IPv4 с местом для гостей (D-51)")
    }

    @Test
    fun downInterfaceIsNotShared() {
        ifaces = listOf(LinuxShareInterfaces.Iface("wlp2s0", false, listOf(ip("10.42.0.1") to 24)))
        assertTrue(shares.find().endpoints.isEmpty())
    }

    @Test
    fun anyDoubtMeansNoSharing() {
        active = CommandResult(SystemCommand.NOT_FOUND, "нет nmcli")
        assertEquals(LinuxShareInterfaces.Source.NO_NMCLI, shares.find().source)
        active = CommandResult(8, "Error: NetworkManager is not running.")
        assertEquals(LinuxShareInterfaces.Source.FAILED, shares.find().source)
        assertEquals("nmcli=8", shares.find().seen)
        active = CommandResult(0, "это не вывод nmcli\n")
        val unparsed = shares.find()
        assertEquals(LinuxShareInterfaces.Source.UNPARSED, unparsed.source)
        assertTrue(unparsed.endpoints.isEmpty())
        // Соединение ушло между вызовами — ответа о нём нет: не общее.
        active = CommandResult(0, "$hotspot:wlp2s0\n")
        methods.remove(hotspot)
        assertTrue(shares.find().endpoints.isEmpty())
        // Интерфейсов не узнать — раздавать не на чем.
        methods[hotspot] = "shared"
        assertTrue(LinuxShareInterfaces(nmcli, { null }, { null }).find().endpoints.isEmpty())
    }

    @Test
    fun terseOutputIsParsedStrictly() {
        assertEquals(listOf("a", "b:c", "d\\e"), LinuxShareInterfaces.splitTerse("a:b\\:c:d\\\\e"))
        assertEquals(listOf(hotspot to "wlp2s0"), LinuxShareInterfaces.parseActive("$hotspot:wlp2s0\n$wired:\n$wired:--\n\n"), "без устройства — пропуск")
        assertNull(LinuxShareInterfaces.parseActive("Hotspot:wlp2s0\n"), "не UUID — лучше не раздавать")
        assertNull(LinuxShareInterfaces.parseActive("$hotspot:wlp2s0:extra\n"))
        assertEquals(emptyList(), LinuxShareInterfaces.parseActive(""))
    }

    @Test
    fun nmcliIsRunByAbsolutePathOnly() {
        assertTrue(LinuxShareInterfaces.NMCLI_BINARIES.all { it.startsWith("/") }, "не из PATH (T17)")
        assertFalse(LinuxShareInterfaces.NMCLI_BINARIES.isEmpty())
    }
}
