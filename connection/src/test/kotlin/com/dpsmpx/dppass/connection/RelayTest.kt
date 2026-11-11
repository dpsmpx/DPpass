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

    private fun draft(name: String = "Redmi", address: String = "", port: Int = 41234, user: String = key(1), password: String = key(2)) =
        RelayDraft(name, address, port, user, password)

    private fun key(n: Int) = java.util.Base64.getEncoder().encodeToString(ByteArray(32) { n.toByte() })

    @Test
    fun protectedLinkRoundTripsAndRejectsLegacyCredentials() {
        val link = RelayLink(GATEWAY, 41234, key(1), key(2), "Мой телефон 👩\u200d💻")
        assertTrue(link.format().startsWith("dppass-relay://"))
        assertEquals(link, RelayLink.parse(link.format()).valueOrNull())
        assertEquals(draft(name = link.name!!), link.draft("Устройство"))
        assertEquals("Устройство", link.copy(name = null).draft("Устройство").name)
        assertEquals(DiagCode.RELAY_ADDRESS_NOT_LOCAL, RelayLink.parse(link.copy(address = IpAddress.parseV4("203.0.113.10")!!).format()).errors.single().code)
        assertEquals(DiagCode.PORT_INVALID, RelayLink.parse(link.copy(port = 70000).format()).errors.single().code)
        val old = "socks5://u:old-password@192.168.43.1:41234"
        assertTrue(RelayLink.looksLike(old))
        val refused = RelayLink.parse(old)
        assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, refused.errors.single().code)
        assertFalse("old-password" in refused.errors.single().message)
    }

    @Test
    fun importRecognizesProtectedLinkAndExplainsOldFormat() {
        val link = RelayLink(GATEWAY, 41234, key(1), key(2), "Redmi")
        assertEquals(ImportKind.Relay(link), ImportClassifier.classify("  ${link.format()} \n"))
        val bad = ImportClassifier.classify("socks5://u-test:p-test@192.168.43.1:41234")
        assertEquals(DiagCode.FORMAT_VERSION_UNSUPPORTED, (bad as ImportKind.Unrecognized).reason?.code)
    }

    @Test
    fun addValidatesStoresAndSurvivesRestart() {
        val s = service()
        val auto = s.add(draft()).valueOrNull()!!
        assertNull(auto.address, "пустой адрес — шлюз сети")
        assertEquals(12, auto.id.length)
        assertEquals(TransportClass.TCP_STREAM, auto.profile(GATEWAY).transportClass)
        assertIs<ProtocolSpec.Shadowsocks>(auto.profile(GATEWAY).protocol)
        val fixed = s.add(draft(name = "USB", address = "10.42.0.1", port = 50000)).valueOrNull()!!
        assertEquals(IpAddress.parseV4("10.42.0.1"), fixed.address)

        // Тот же вход (адрес, порт, логин) — обновление, а не копия.
        val updated = s.add(draft(name = "Redmi 13", password = key(3))).valueOrNull()!!
        assertEquals(auto.id, updated.id)
        assertEquals(auto.addedAtMillis, updated.addedAtMillis)
        assertEquals(2, s.list().valueOrNull()!!.size)

        val again = service().list().valueOrNull()!!
        assertEquals(listOf("Redmi 13", "USB"), again.map { it.name }, "переживает перезапуск")
        assertEquals(key(3), again.first().password.reveal())

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
        assertEquals(listOf(DiagCode.PASSWORD_FORMAT_INVALID to "password"), codes(draft(password = "")))
        assertEquals(listOf(DiagCode.PASSWORD_FORMAT_INVALID to "user"), codes(draft(user = "")))
        assertEquals(listOf(DiagCode.PASSWORD_FORMAT_INVALID to "password"), codes(draft(password = "p".repeat(256))))
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
        val stored = RelayCodec.write(listOf(RelayDevice("0123456789ab", "R", null, 1, Secret("u"), Secret("p"), 0)))
            .replace("\"port\"", "\"address\":\"203.0.113.10\",\"port\"")
        assertIs<Outcome.Failure>(RelayCodec.read(stored))
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

    @Test
    fun relayHealthFailureNamesTheSharingPhone() = runBlocking {
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))
        val device = core.relays.add(draft()).valueOrNull()!!
        // Вход раздачи ответил, а данных нет (D-59): причина — у раздающего телефона, исходная — в цепочке.
        for (code in listOf(DiagCode.ENDPOINT_UNREACHABLE, DiagCode.PAYLOAD_STALLED, DiagCode.HEALTH_CHECK_FAILED, DiagCode.TLS_HANDSHAKE_FAILED)) {
            val failed = assertIs<ConnectionReport.Failed>(core.connectVia(device, GATEWAY, HealthChecker { _, _ -> Outcome.failure(code, "проба") }, null) {})
            assertEquals(DiagCode.RELAY_UPSTREAM_FAILED, failed.reason.code, code.name)
            assertTrue("раздающем телефоне" in failed.reason.message)
            assertEquals(code, failed.reason.causes.single().code)
        }
        // Отказ не проверки здоровья — со своим кодом.
        val other = assertIs<ConnectionReport.Failed>(
            core.connectVia(device, GATEWAY, HealthChecker { _, _ -> Outcome.failure(DiagCode.INTERNAL_ERROR, "сбой") }, null) {},
        )
        assertEquals(DiagCode.ATTEMPTS_EXHAUSTED, other.reason.code)
    }
}
