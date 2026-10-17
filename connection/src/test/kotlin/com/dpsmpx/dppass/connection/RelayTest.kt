package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.IpAddress
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

private val GATEWAY = IpAddress.parseV4("192.168.43.1")!!

/** Устройство раздачи (D-55): ссылка, хранение, добавление, вход SOCKS5, подключение через него. */
class RelayTest {
    private val clock = ManualClock(1_000)
    private val blobs = InMemoryBlobStore()

    private fun service() = RelayService(RelayStore(blobs, Quarantine(blobs, clock)), clock)

    private fun draft(name: String = "Redmi", address: String = "", port: Int = 41234, user: String = "u-test", password: String = "p-test-0123456789") =
        RelayDraft(name, address, port, user, password)

    @Test
    fun linkRoundTripsAndKeepsOnlyPrivateIpv4() {
        val link = RelayLink(GATEWAY, 41234, "u test+1", "p:@/#%", "Мой телефон")
        val text = link.format()
        assertTrue(text.startsWith("socks5://"), text)
        assertEquals(link, RelayLink.parse(text).valueOrNull())
        assertEquals(RelayLink(GATEWAY, 41234, "u", "p", null), RelayLink.parse("SOCKS5://u:p@192.168.43.1:41234").valueOrNull())
        for (bad in listOf("socks5://u:p@203.0.113.10:41234", "socks5://u:p@relay.example.org:41234", "socks5://u:p@[fd00::1]:41234")) {
            val r = RelayLink.parse(bad)
            assertIs<Outcome.Failure>(r, bad)
            assertTrue(r.errors.single().code in setOf(DiagCode.RELAY_ADDRESS_NOT_LOCAL, DiagCode.VALUE_UNKNOWN), bad)
        }
        assertEquals(DiagCode.RELAY_ADDRESS_NOT_LOCAL, RelayLink.parse("socks5://u:p@203.0.113.10:41234").errors.single().code)
        assertEquals(DiagCode.VALUE_UNKNOWN, RelayLink.parse("socks5://u@192.168.43.1:41234").errors.single().code, "без пароля")
        assertEquals(DiagCode.PORT_INVALID, RelayLink.parse("socks5://u:p@192.168.43.1:70000").errors.single().code)
        // Причина — без значений из ссылки (T3).
        assertFalse(RelayLink.parse("socks5://u:secret-value@203.0.113.10:1").errors.single().message.contains("secret-value"))
        // Черновик из ссылки — адрес шлюза: подсеть раздачи Android меняет.
        assertEquals(draft(name = "Мой телефон", user = "u test+1", password = "p:@/#%"), link.draft("Устройство"))
        assertEquals("Устройство", link.copy(name = null).draft("Устройство").name)
    }

    @Test
    fun importRecognizesRelayLinkOnly() {
        val kind = ImportClassifier.classify("  socks5://u-test:p-test@192.168.43.1:41234#Redmi \n")
        assertEquals(ImportKind.Relay(RelayLink(GATEWAY, 41234, "u-test", "p-test", "Redmi")), kind)
        val bad = ImportClassifier.classify("socks5://u-test:p-test@203.0.113.10:41234")
        assertEquals(DiagCode.RELAY_ADDRESS_NOT_LOCAL, (bad as ImportKind.Unrecognized).reason?.code)
    }

    @Test
    fun addValidatesStoresAndSurvivesRestart() {
        val s = service()
        val auto = s.add(draft()).valueOrNull()!!
        assertNull(auto.address, "пустой адрес — шлюз сети")
        assertEquals(12, auto.id.length)
        assertEquals(TransportClass.LOCAL_RELAY, auto.profile(GATEWAY).transportClass)
        assertIs<ProtocolSpec.Socks>(auto.profile(GATEWAY).protocol)
        val fixed = s.add(draft(name = "USB", address = "10.42.0.1", port = 50000)).valueOrNull()!!
        assertEquals(IpAddress.parseV4("10.42.0.1"), fixed.address)

        // Тот же вход (адрес, порт, логин) — обновление, а не копия.
        val updated = s.add(draft(name = "Redmi 13", password = "p-new-0123456789")).valueOrNull()!!
        assertEquals(auto.id, updated.id)
        assertEquals(auto.addedAtMillis, updated.addedAtMillis)
        assertEquals(2, s.list().valueOrNull()!!.size)

        val again = service().list().valueOrNull()!!
        assertEquals(listOf("Redmi 13", "USB"), again.map { it.name }, "переживает перезапуск")
        assertEquals("p-new-0123456789", again.first().password.reveal())

        assertEquals("Телефон", s.rename(auto.id, "  Телефон ").valueOrNull()!!.name)
        assertIs<Outcome.Success<Unit>>(s.remove(fixed.id))
        assertEquals(listOf(auto.id), service().list().valueOrNull()!!.map { it.id })
    }

    @Test
    fun badDraftsAreRefusedWithReasonAndPath() {
        fun codes(d: RelayDraft) = RelayService.validate(d).map { it.code to it.path }
        assertEquals(emptyList(), codes(draft()))
        assertEquals(listOf(DiagCode.RELAY_ADDRESS_NOT_LOCAL to "address"), codes(draft(address = "203.0.113.10")))
        assertEquals(listOf(DiagCode.RELAY_ADDRESS_NOT_LOCAL to "address"), codes(draft(address = "relay.example.org")))
        assertEquals(listOf(DiagCode.NAME_INVALID to "name"), codes(draft(name = " ")))
        assertEquals(listOf(DiagCode.PORT_INVALID to "port"), codes(draft(port = 0)))
        assertEquals(listOf(DiagCode.PASSWORD_EMPTY to "password"), codes(draft(password = "")))
        assertEquals(listOf(DiagCode.PASSWORD_EMPTY to "user"), codes(draft(user = "")))
        assertEquals(listOf(DiagCode.LIMIT_EXCEEDED to "password"), codes(draft(password = "p".repeat(256))))
        assertIs<Outcome.Failure>(service().add(draft(address = "8.8.8.8")))
        assertTrue(service().list().valueOrNull()!!.isEmpty(), "отказ ничего не сохраняет")
    }

    @Test
    fun listIsLimited() {
        val s = service()
        repeat(RelayService.MAX_DEVICES) { assertIs<Outcome.Success<*>>(s.add(draft(port = 20000 + it))) }
        assertEquals(DiagCode.LIMIT_EXCEEDED, s.add(draft(port = 30000)).errors.single().code)
        assertIs<Outcome.Success<*>>(s.add(draft(port = 20000)), "обновление существующего — не новое")
    }

    @Test
    fun unreadableListGoesToQuarantineAndStartsEmpty() {
        blobs.write(RelayStore.KEY, """{"format":"dppass.relays","format_version":1,"devices":[{"id":"zz"}]}""".toByteArray())
        val r = service().list()
        assertEquals(emptyList(), r.valueOrNull())
        assertTrue(r.diagnostics.any { it.code == DiagCode.STORAGE_CORRUPTED })
        assertEquals(1, Quarantine(blobs, clock).list().valueOrNull()!!.size)
        // Адрес вне своей сети в записи — тоже нечитаемо, а не «как-нибудь».
        val stored = RelayCodec.write(listOf(RelayDevice("0123456789ab", "R", null, 1, Secret("u"), Secret("p"), 0))).replace("\"port\"", "\"address\":\"203.0.113.10\",\"port\"")
        assertIs<Outcome.Failure>(RelayCodec.read(stored))
    }

    @Test
    fun socks5LoginTellsAcceptedRejectedAndForeign() {
        fun run(reply: ByteArray): Pair<Socks5Login.Result, ByteArray> {
            val sent = ByteArrayOutputStream()
            val r = Socks5Login.check(ByteArrayInputStream(reply), sent, Secret("u1"), Secret("p12"))
            return r to sent.toByteArray()
        }
        val (ok, sent) = run(byteArrayOf(5, 2, 1, 0))
        assertEquals(Socks5Login.Result.ACCEPTED, ok)
        // Приветствие: версия 5, один метод — логин и пароль; затем RFC 1929: 1, длина, логин, длина, пароль.
        assertEquals(listOf<Byte>(5, 1, 2, 1, 2, 'u'.code.toByte(), '1'.code.toByte(), 3, 'p'.code.toByte(), '1'.code.toByte(), '2'.code.toByte()), sent.toList())
        assertEquals(Socks5Login.Result.REJECTED, run(byteArrayOf(5, 2, 1, 1)).first)
        assertEquals(Socks5Login.Result.NOT_SOCKS, run(byteArrayOf(5, 0)).first, "вход без пароля — не вход раздачи")
        assertEquals(Socks5Login.Result.NOT_SOCKS, run("HTTP/1.1 400".toByteArray()).first)
        assertEquals(Socks5Login.Result.NOT_SOCKS, run(byteArrayOf()).first)
    }

    @Test
    fun connectViaUsesOnlyTheDeviceWithUsersRoutingAndKeepsActivation() = runBlocking {
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))
        val device = core.relays.add(draft()).valueOrNull()!!
        val ir = core.relayConfig(device, GATEWAY)
        assertEquals(listOf(device.profileId), ir.profiles.map { it.id })
        assertEquals(Host.Ip(GATEWAY), ir.profiles.single().endpoint.host)
        val report = core.connectVia(device, GATEWAY, HealthChecker { _, _ -> Outcome.Success(Unit) }, null) {}
        val connected = assertIs<ConnectionReport.Connected>(report)
        assertEquals(device.profileId, connected.profileId)
        assertTrue("выбран пользователем" in connected.plan.attempts.single().reasons)
        assertNull(core.activation.state.active, "подключение через устройство не активирует конфигурацию")
        connected.session.stop()

        // Отказ устройства — отказ подключения, без подстановки других серверов.
        val failed = core.connectVia(device, GATEWAY, HealthChecker { _, _ -> Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "нет ответа") }, null) {}
        assertIs<ConnectionReport.Failed>(failed)
        assertEquals(1, failed.attempts.size)
    }
}
