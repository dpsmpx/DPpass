package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.engine.ConnNetwork
import com.dpsmpx.dppass.engine.ConnState
import com.dpsmpx.dppass.engine.EngineConnection
import com.dpsmpx.dppass.engine.InboundKind
import com.dpsmpx.dppass.engine.RouteKind
import java.io.File
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** Процесс у соединения на ПК (D-106): таблицы сокетов Linux и Windows, поиск по адресам снимка ядра. Данные синтетические. */
class SocketOwnersTest {
    private val proc: File = createTempDirectory("dppass-proc").toFile()

    @AfterTest
    fun cleanup() {
        proc.deleteRecursively()
    }

    private fun conn(
        source: String,
        target: String,
        network: ConnNetwork = ConnNetwork.TCP,
        inbound: InboundKind = InboundKind.TUN,
    ) = EngineConnection(
        id = 1, network = network, inbound = "tun-in", source = source, target = target, domain = "", protocol = "", route = "proxy",
        state = ConnState.OPEN, ageMillis = 1, durationMillis = 1, idleMillis = 0, firstByteMillis = -1, upBytes = 0, downBytes = 0,
        upChunks = 0, downChunks = 0, routeKind = RouteKind.PROXY, inboundKind = inbound,
    )

    private fun write(path: String, text: String) = File(proc, path).apply { parentFile.mkdirs() }.writeText(text)

    private fun socket(pid: Int, fd: Int, inode: Long, comm: String) {
        val dir = File(proc, "$pid/fd").apply { mkdirs() }
        Files.createSymbolicLink(File(dir, fd.toString()).toPath(), File("socket:[$inode]").toPath())
        write("$pid/comm", "$comm\n")
    }

    @Test
    fun linuxTablesGiveTheProcessByAddressesOfTheCoreSnapshot() {
        val head = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
        // 172.19.0.1:40000 → 198.51.100.7:443 (TCP), 0.0.0.0:5353 (UDP), [2001:db8::1]:50000 → [2001:db8::7]:443 (TCP6).
        write("net/tcp", head + "   0: 010013AC:9C40 076433C6:01BB 01 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 20 4 30 10 -1\n")
        write("net/udp", head + "   0: 00000000:14E9 00000000:0000 07 00000000:00000000 00:00000000 00000000  1000        0 4343 2 0 0\n")
        val v6 = "B80D0120000000000000000001000000:C350 B80D0120000000000000000007000000:01BB"
        write("net/tcp6", head + "   0: $v6 01 00000000:00000000 00:00000000 00000000  1000        0 4444 1 0 20 4 30 10 -1\n")
        socket(1234, 5, 4242, "firefox")
        socket(1234, 6, 4343, "firefox")
        socket(2345, 3, 4444, "curl")
        File(proc, "2345/fd/4").let { Files.createSymbolicLink(it.toPath(), File("/dev/null").toPath()) }

        val sockets = LinuxSockets.read(proc)!!
        assertEquals(3, sockets.size)
        val owners = SocketOwners({ LinuxSockets.read(proc) })
        assertEquals("firefox", owners.owner(conn("172.19.0.1:40000", "198.51.100.7:443")))
        assertEquals("firefox", owners.owner(conn("172.19.0.1:5353", "198.51.100.53:53", ConnNetwork.UDP)), "UDP без connect — по порту")
        assertEquals("curl", owners.owner(conn("[2001:db8::1]:50000", "[2001:db8::7]:443")))
        assertNull(owners.owner(conn("172.19.0.1:40000", "198.51.100.7:443", inbound = InboundKind.SHARE)), "раздача — другое устройство")
    }

    @Test
    fun tableIsReadAtMostOncePerIntervalAndOnlyOnMiss() {
        var reads = 0
        val clock = ManualClock(10_000)
        val owners = SocketOwners({
            reads++
            listOf(OwnedSocket(ConnNetwork.TCP, "172.19.0.1:40000", "198.51.100.7:443", "app"))
        }, clock)
        assertEquals("app", owners.owner(conn("172.19.0.1:40000", "198.51.100.7:443")))
        assertEquals("app", owners.owner(conn("172.19.0.1:40000", "198.51.100.7:443")))
        assertNull(owners.owner(conn("172.19.0.1:40001", "198.51.100.7:443")))
        assertEquals(1, reads, "известное — из памяти; неизвестное — не чаще раза в секунду")
        clock.advance(1_000)
        assertNull(owners.owner(conn("172.19.0.1:40001", "198.51.100.7:443")))
        assertEquals(2, reads)
    }

    @Test
    fun windowsAnswerOfTheBridge() {
        val text = "tcp\t172.19.0.1:40000\t198.51.100.7:443\t4242\tfirefox.exe\nudp\t[::]:5353\t\t4\t\nbad line"
        val sockets = WindowsSockets.parse(byteArrayOf(0) + text.encodeToByteArray())!!
        assertEquals(listOf("firefox.exe", "pid 4"), sockets.map { it.owner })
        assertNull(sockets[1].remote)
        assertNull(WindowsSockets.parse(byteArrayOf(2) + "отказ".encodeToByteArray()), "отказ моста — таблицы нет")
        val owners = SocketOwners({ sockets })
        assertEquals("pid 4", owners.owner(conn("[2001:db8::1]:5353", "[2001:db8::53]:53", ConnNetwork.UDP)))
    }

    @Test
    fun addressesAreComparedInOneForm() {
        assertEquals("198.51.100.8:443", SocketOwners.normal("[::ffff:198.51.100.8]:443"))
        assertEquals("[2001:db8::1]:80", SocketOwners.normal("[2001:0db8:0:0:0:0:0:1]:80"))
        assertEquals("198.51.100.8:443", SocketOwners.normal("198.51.100.8:443"))
    }
}
