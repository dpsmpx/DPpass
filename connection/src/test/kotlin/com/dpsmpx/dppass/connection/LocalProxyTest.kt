package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.EngineSession
import com.dpsmpx.dppass.engine.ProxyEngine
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.XrayBackend
import com.dpsmpx.dppass.engine.xray.XrayCompiler
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.Quarantine
import kotlinx.coroutines.runBlocking
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Подключение без VPN (D-95): настройки локального прокси, свободный порт, отказ без вины серверов. */
class LocalProxyTest {
    private val clock = ManualClock(1_000)
    private val blobs = InMemoryBlobStore()

    @Test
    fun freshSettingsAreRandomAndOff() {
        val a = LocalProxySettings.generate()
        val b = LocalProxySettings.generate()
        assertFalse(a.enabled, "по умолчанию — через VPN")
        assertNull(a.spec())
        assertTrue(a.port in ShareSettings.PORT_FROM until ShareSettings.PORT_UNTIL)
        assertEquals(ShareSettings.PASSWORD_LENGTH, a.password.reveal().length)
        assertNotEquals(a.password, b.password, "пароль — случайный")
        val on = a.copy(enabled = true)
        assertEquals(a.port, on.spec()!!.port)
        assertEquals("socks5://${a.user.reveal()}:${a.password.reveal()}@127.0.0.1:${a.port}", on.link())
        assertFalse(a.password.reveal() in a.toString(), "пароль не попадает в журнал через toString")
    }

    @Test
    fun storeKeepsSettingsAndQuarantinesWhatItCannotRead() {
        val store = LocalProxyStore(blobs, Quarantine(blobs, clock))
        val first = store.load().valueOrNull()!!
        assertEquals(first, store.load().valueOrNull(), "записи не было — новые настройки сохранены")
        val on = first.copy(enabled = true)
        assertTrue(store.save(on) is Outcome.Success)
        assertEquals(on, store.load().valueOrNull())
        blobs.write(LocalProxyStore.KEY, LocalProxyCodec.write(on).replace("\"enabled\":true", "\"enabled\":true,\"listen\":\"0.0.0.0\"").toByteArray())
        val r = store.load()
        val fresh = r.valueOrNull()!!
        assertFalse(fresh.enabled, "не прочиталось — режим выключен")
        assertNotEquals(on.password, fresh.password, "и пароль новый")
        assertTrue(r.diagnostics.any { it.code == DiagCode.STORAGE_CORRUPTED })
        assertTrue(Quarantine(blobs, clock).list().valueOrNull()!!.isNotEmpty(), "исходник — в карантине")
    }

    @Test
    fun busyPortIsReplacedAndSavedNoFreePortIsARefusal() {
        val busy = mutableSetOf<Int>()
        val service = LocalProxyService(LocalProxyStore(blobs, Quarantine(blobs, clock)), SecureRandom(), isFree = { it !in busy })
        assertEquals(Outcome.Success(null), service.prepare(), "выключено — входа нет")
        val on = service.setEnabled(true).valueOrNull()!!
        assertEquals(on.port, service.prepare().valueOrNull()!!.port)
        busy += on.port
        val moved = service.prepare()
        val port = moved.valueOrNull()!!.port
        assertNotEquals(on.port, port)
        assertTrue(moved.diagnostics.single().code == DiagCode.LOCAL_PROXY_PORT_CHANGED)
        assertEquals(port, LocalProxyStore(blobs, Quarantine(blobs, clock)).load().valueOrNull()!!.port, "новый порт сохранён")
        assertEquals(on.password, service.current().valueOrNull()!!.password, "пароль прежний")
        val none = LocalProxyService(LocalProxyStore(blobs, Quarantine(blobs, clock)), SecureRandom(), isFree = { false }).prepare()
        assertTrue(none is Outcome.Failure && none.errors.single().code == DiagCode.LOCAL_PROXY_UNAVAILABLE, none.toString())
    }

    @Test
    fun portProbeSeesARealListener() {
        ServerSocket().use { s ->
            s.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0))
            assertFalse(LocalPorts.isFree(s.localPort), "порт занят слушателем")
        }
    }

    /** Ядро, у которого локальный вход не встаёт: порт заняли между проверкой и запуском. */
    private class LocalCannotBind : ProxyEngine {
        override val capabilities = XrayBackend.CAPABILITIES
        var starts = 0

        override suspend fun validate(config: CompiledConfig): Outcome<Unit> = Outcome.Success(Unit)

        override suspend fun start(config: CompiledConfig, tun: TunInput?): Outcome<EngineSession> {
            starts++
            check("\"${XrayBackend.TAG_LOCAL}\"" in config.payloadForEngine()) { "в конфигурации нет локального входа" }
            return Outcome.failure(DiagCode.BACKEND_START_FAILED, "listen tcp 127.0.0.1:41235: bind: address already in use")
        }
    }

    @Test
    fun localProxyThatCannotBindStopsThePlanWithoutBlamingServers() = runBlocking {
        val multi = ir("valid-multi.json")
        val book = HealthBook()
        val plan = CandidatePlanner.plan(multi, XrayBackend.CAPABILITIES, null, book, null, 0)
        val engine = LocalCannotBind()
        val local = LocalProxySettings.generate().copy(enabled = true).spec()!!
        val pauses = mutableListOf<Long>()
        val log = Logger("t", MemoryLogSink(), clock::nowMillis)
        val report = ConnectionOrchestrator(XrayCompiler(), engine, { _, _ -> Outcome.Success(Unit) }, book, clock, log) { pauses += it }
            .connect(multi, plan, null, local = local)
        val failed = assertIs<ConnectionReport.Failed>(report)
        assertEquals(DiagCode.LOCAL_PROXY_UNAVAILABLE, failed.reason.code)
        assertEquals(1, engine.starts, "следующие кандидаты упёрлись бы в тот же порт")
        assertTrue(pauses.isEmpty())
        assertTrue(plan.attempts.all { book.of(it.profile.id).state == HealthState.UNKNOWN }, "ни один сервер не наказан")
    }
}
