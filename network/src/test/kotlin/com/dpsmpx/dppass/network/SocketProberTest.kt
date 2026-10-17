package com.dpsmpx.dppass.network

import com.dpsmpx.dppass.core.Clock
import kotlinx.coroutines.runBlocking
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.SecureRandom
import javax.net.ssl.SSLHandshakeException
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Исходы проб на настоящих сокетах (D-60): локальные серверы вместо ориентиров. */
class SocketProberTest {
    private val loopback = InetAddress.getLoopbackAddress()

    private class FakeNetwork(
        private val addresses: () -> List<InetAddress>,
        private val captive: Boolean? = null,
    ) : ProbeNetwork {
        override fun resolve(host: String): List<InetAddress> = addresses()
        override fun tcpSocket(): Socket = Socket()
        override fun udpSocket(): DatagramSocket = DatagramSocket()
        override fun captivePortal(): Boolean? = captive
    }

    /** Без TLS: тест проверяет пробу, а не платформенный TLS. */
    private val plain = TlsLayer { s, _, _ -> s }

    private fun prober(
        port: Int,
        network: ProbeNetwork = FakeNetwork({ listOf(loopback) }),
        tls: TlsLayer = plain,
        bulkPath: String? = "/__down?bytes=65536",
        udpPort: Int? = null,
    ) = SocketProber(
        network, Clock.MONOTONIC, SecureRandom(),
        landmarks = { Landmark("probe.example.org", port, bulkPath) },
        tls = tls, udpPort = udpPort, timeoutMillis = 700, bulkDeadlineMillis = 1_500, bogon = { false },
    )

    private fun run(p: SocketProber, kind: ProbeKind) = runBlocking { p.probe(ProbeRequest(kind, ProbeTarget.FOREIGN)) }

    private fun freePort(): Int = ServerSocket(0, 1, loopback).use { it.localPort }

    @Test
    fun dnsTellsAnswerFromTamperingAndSilence() {
        fun dns(vararg a: String) = runBlocking {
            SocketProber(FakeNetwork({ a.map { InetAddress.getByAddress(ipv4(it)) } }), Clock.MONOTONIC, SecureRandom())
                .probe(ProbeRequest(ProbeKind.DNS, ProbeTarget.FOREIGN)).outcome
        }
        assertEquals(ProbeOutcome.SUCCESS, dns("203.0.113.10"))
        assertEquals(ProbeOutcome.SUCCESS, dns("10.0.0.1", "203.0.113.10"), "есть публичный — ответ")
        assertEquals(ProbeOutcome.DNS_TAMPERED, dns("0.0.0.0"))
        assertEquals(ProbeOutcome.DNS_TAMPERED, dns("10.10.10.10", "127.0.0.1"))
        assertEquals(ProbeOutcome.DNS_TAMPERED, dns("100.64.0.1"), "адрес CGNAT — не ответ на публичное имя")
        assertEquals(ProbeOutcome.UNREACHABLE, dns())
        val silent = SocketProber(FakeNetwork({ throw UnknownHostException("нет") }), Clock.MONOTONIC, SecureRandom())
        assertEquals(ProbeOutcome.UNREACHABLE, runBlocking { silent.probe(ProbeRequest(ProbeKind.DNS, ProbeTarget.FOREIGN)).outcome })
        assertEquals(ProbeOutcome.UNREACHABLE, runBlocking { silent.probe(ProbeRequest(ProbeKind.TCP, ProbeTarget.FOREIGN)).outcome }, "без имени — пути нет")
    }

    @Test
    fun tcpAndTlsOutcomes() {
        ServerSocket(0, 4, loopback).use { server ->
            val accept = thread(isDaemon = true) { repeat(3) { runCatching { server.accept().close() } } }
            val ok = run(prober(server.localPort), ProbeKind.TCP)
            assertEquals(ProbeOutcome.SUCCESS, ok.outcome)
            assertNotNull(ok.latencyMillis)
            assertEquals(ProbeOutcome.SUCCESS, run(prober(server.localPort), ProbeKind.TLS).outcome)
            val broken = TlsLayer { _, _, _ -> throw SSLHandshakeException("сброшено") }
            assertEquals(ProbeOutcome.RESET, run(prober(server.localPort, tls = broken), ProbeKind.TLS).outcome)
            accept.join(1_000)
        }
        ServerSocket(0, 1, loopback).use { server ->
            val slow = TlsLayer { _, _, _ -> throw SocketTimeoutException("нет ответа") }
            val r = run(prober(server.localPort, tls = slow), ProbeKind.TLS)
            assertEquals(ProbeOutcome.TIMEOUT, r.outcome)
            assertNull(r.latencyMillis, "у отказа задержки нет")
        }
        assertEquals(ProbeOutcome.REFUSED, run(prober(freePort()), ProbeKind.TCP).outcome)
    }

    @Test
    fun udpCountsOnlyAReplyToOurInitial() {
        fun server(answer: (ByteArray, Int) -> ByteArray?): DatagramSocket = DatagramSocket(0, loopback).also { s ->
            thread(isDaemon = true) {
                val buf = ByteArray(2048)
                val p = DatagramPacket(buf, buf.size)
                runCatching {
                    s.receive(p)
                    answer(p.data, p.length)?.let { s.send(DatagramPacket(it, it.size, p.socketAddress)) }
                }
            }
        }
        var seen = 0
        server { data, length ->
            seen = length
            // Назначение ответа — идентификатор источника клиента: байты 15..22 его Initial.
            byteArrayOf(0xC0.toByte(), 0, 0, 0, 1, 8) + data.copyOfRange(15, 23) + ByteArray(30)
        }.use { s ->
            assertEquals(ProbeOutcome.SUCCESS, run(prober(443, udpPort = s.localPort), ProbeKind.UDP).outcome)
            assertTrue(seen >= QuicInitial.MIN_DATAGRAM, "ушла полная датаграмма: $seen")
        }
        server { _, _ -> byteArrayOf(0xC0.toByte(), 0, 0, 0, 1, 8) + ByteArray(38) }.use { s ->
            assertEquals(ProbeOutcome.TIMEOUT, run(prober(443, udpPort = s.localPort), ProbeKind.UDP).outcome, "чужое соединение — не ответ")
        }
        server { _, _ -> null }.use { s ->
            assertEquals(ProbeOutcome.TIMEOUT, run(prober(443, udpPort = s.localPort), ProbeKind.UDP).outcome)
        }
    }

    @Test
    fun bulkSeesFullTransferStallAndForeignAnswer() {
        fun server(respond: (Socket) -> Unit): ServerSocket = ServerSocket(0, 1, loopback).also { s ->
            thread(isDaemon = true) {
                runCatching {
                    s.accept().use { c ->
                        val head = StringBuilder()
                        val input = c.getInputStream()
                        while (!head.endsWith("\r\n\r\n")) head.append(input.read().toChar())
                        requests += head.toString()
                        respond(c)
                    }
                }
            }
        }
        val ok = "HTTP/1.1 200 OK\r\nContent-Length: 65536\r\n\r\n".toByteArray()
        server { c -> c.getOutputStream().apply { write(ok); write(ByteArray(65_536)); flush() } }.use { s ->
            val r = run(prober(s.localPort), ProbeKind.BULK)
            assertEquals(ProbeOutcome.SUCCESS, r.outcome)
            assertNotNull(r.latencyMillis)
        }
        val request = requests.single()
        assertTrue(request.startsWith("GET /__down?bytes=65536 HTTP/1.1\r\n"), request)
        assertTrue("Host: probe.example.org\r\n" in request && "User-Agent: DPpass\r\n" in request, request)

        // 16 КБ и тишина — «замерзание» (L7): соединение есть, данных больше нет.
        server { c ->
            c.getOutputStream().apply { write(ok); write(ByteArray(16_384)); flush() }
            Thread.sleep(2_500)
        }.use { s -> assertEquals(ProbeOutcome.STALLED, run(prober(s.localPort), ProbeKind.BULK).outcome) }
        // 16 КБ и обрыв — тоже встало на объёме.
        server { c -> c.getOutputStream().apply { write(ok); write(ByteArray(16_384)); flush() } }.use { s ->
            assertEquals(ProbeOutcome.STALLED, run(prober(s.localPort), ProbeKind.BULK).outcome)
        }
        // Ответ не 2xx: о сети проба ничего не сказала.
        server { c -> c.getOutputStream().apply { write("HTTP/1.1 403 Forbidden\r\n\r\n".toByteArray()); flush() } }.use { s ->
            assertEquals(ProbeOutcome.INCONCLUSIVE, run(prober(s.localPort), ProbeKind.BULK).outcome)
        }
        // Ничего не ответил вовсе — тайм-аут, а не «замерзание».
        server { Thread.sleep(2_500) }.use { s -> assertEquals(ProbeOutcome.TIMEOUT, run(prober(s.localPort), ProbeKind.BULK).outcome) }
        assertEquals(ProbeOutcome.INCONCLUSIVE, run(prober(freePort(), bulkPath = null), ProbeKind.BULK).outcome, "ориентир без адреса объёма")
    }

    @Test
    fun captivePortalComesFromTheSystem() {
        fun captive(c: Boolean?) = runBlocking {
            SocketProber(FakeNetwork({ emptyList() }, c), Clock.MONOTONIC, SecureRandom()).probe(ProbeRequest(ProbeKind.CAPTIVE, ProbeTarget.DOMESTIC)).outcome
        }
        assertEquals(ProbeOutcome.REDIRECTED, captive(true))
        assertEquals(ProbeOutcome.SUCCESS, captive(false))
        assertEquals(ProbeOutcome.INCONCLUSIVE, captive(null))
    }

    @Test
    fun inconclusiveProbesAreNotEvidence() {
        val all = ProbePlan.STANDARD.map { ProbeResult(it, ProbeOutcome.INCONCLUSIVE) }
        val x = NetworkClassifier.classify(NetworkType.WIFI, all)
        assertEquals(RestrictionClass.UNKNOWN, x.restriction, x.evidence.toString())
        assertEquals(Reachability.UNKNOWN, x.bulk)
    }

    private val requests = java.util.Collections.synchronizedList(mutableListOf<String>())

    private fun ipv4(s: String): ByteArray = s.split('.').map { it.toInt().toByte() }.toByteArray()
}
