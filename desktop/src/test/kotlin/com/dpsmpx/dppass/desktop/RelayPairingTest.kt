package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.Pairing
import com.dpsmpx.dppass.connection.RelayService
import com.dpsmpx.dppass.connection.RelayStore
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.net.SocketAddress
import java.security.SecureRandom
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Сопряжение ПК-гостя (D-85, к D-56): настоящий ход хозяина по loopback, код на обоих экранах, вход — в доверенные. */
class RelayPairingTest {
    private val clock = ManualClock(1_000_000)
    private val blobs = InMemoryBlobStore()
    private val relays = RelayService(RelayStore(blobs, Quarantine(blobs, clock)), clock)
    private val sink = MemoryLogSink()
    private val log = Logger("test", sink, clock::nowMillis)
    private val random = SecureRandom()
    private val server = ServerSocket(0, 1, InetAddress.getLoopbackAddress())
    private val dialed = mutableListOf<String>()

    /** Шлюз Wi-Fi телефона — 192.168.43.1; соединение уходит на loopback, где ждёт хозяин. */
    private val networks = LinuxRelayNetworks(
        sockets = {
            object : Socket() {
                override fun connect(endpoint: SocketAddress, timeout: Int) {
                    val a = endpoint as InetSocketAddress
                    dialed += "${a.address.hostAddress}:${a.port}"
                    super.connect(InetSocketAddress(InetAddress.getLoopbackAddress(), server.localPort), timeout)
                }
            }
        },
        route = { "h\nwlp2s0\t00000000\t012BA8C0\t3\t0\t0\t600\t00000000\n" },
        medium = { LinuxRelayNetworks.Medium.WIFI },
        interfaces = { emptyList() },
    )

    private fun host(says: Boolean, code: AtomicReference<String>) = thread(isDaemon = true) {
        server.accept().use { s ->
            runBlocking {
                Pairing.host(s.getInputStream(), s.getOutputStream(), random, { c -> code.set(c); says }) {
                    Outcome.Success(Pairing.Offer(41234, "guest001", "synthetic-password-01", "Телефон"))
                }
            }
        }
    }

    @Test
    fun bothConfirmAndTheDeviceIsTrustedWithItsOwnLogin() {
        val hostCode = AtomicReference<String>()
        val guestCode = AtomicReference<String>()
        val h = host(true, hostCode)
        val r = runBlocking { RelayPairing.pair(networks, relays, log, random) { c -> guestCode.set(c); true } }
        h.join(10_000)
        server.close()
        val d = assertIs<Outcome.Success<com.dpsmpx.dppass.connection.RelayDevice>>(r).value
        assertEquals(hostCode.get(), guestCode.get(), "один код на обоих экранах")
        assertEquals(Pairing.CODE_DIGITS, guestCode.get().length)
        assertEquals("Телефон", d.name)
        assertEquals(41234, d.port)
        assertEquals("guest001", d.user.reveal())
        assertNull(d.address, "адрес — шлюз сети при каждом подключении, не запомненный")
        assertEquals(listOf("192.168.43.1:${Pairing.PORT}"), dialed, "на шлюз сети ПК, порт сопряжения")
        assertEquals(listOf(d), relays.list().valueOrNull())
        assertTrue(sink.snapshot().any { it.event == "relay_paired" })
        assertTrue(sink.snapshot().none { e -> e.fields.values.any { "synthetic-password" in it || "guest001" in it } }, "входа в журнале нет")
    }

    @Test
    fun codeNotConfirmedOnThePhoneAddsNothing() {
        val h = host(false, AtomicReference())
        val r = runBlocking { RelayPairing.pair(networks, relays, log, random) { true } }
        h.join(10_000)
        server.close()
        assertEquals(DiagCode.PAIRING_REFUSED, assertIs<Outcome.Failure>(r).errors.first().code)
        assertTrue(relays.list().valueOrNull().orEmpty().isEmpty())
    }

    @Test
    fun nobodyWaitingIsItsOwnReason() {
        server.close()
        val r = runBlocking { RelayPairing.pair(networks, relays, log, random) { error("код без хозяина не показывается") } }
        assertEquals(DiagCode.PAIRING_NOT_FOUND, assertIs<Outcome.Failure>(r).errors.single().code)
    }
}
