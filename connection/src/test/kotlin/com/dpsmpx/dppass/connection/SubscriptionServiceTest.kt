package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.routing.DnsTransport
import com.dpsmpx.dppass.storage.EncryptingBlobStore
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.KeyProvider
import com.dpsmpx.dppass.storage.Quarantine
import com.dpsmpx.dppass.subscriptions.DeviceId
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionRequest
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionsState
import com.dpsmpx.dppass.subscriptions.TrafficInfo
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

private const val URL = "https://sub.example.com/api/sub/token-0123456789"
private const val LINKS = "vless://00000000-0000-4000-8000-000000000031@203.0.113.31:443?security=tls&sni=a.example.com#A\n" +
    "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"

class SubscriptionBookTest {
    private val clock = ManualClock(1_000)

    @Test
    fun roundTripKeepsEverything() {
        val blobs = InMemoryBlobStore()
        val book = SubscriptionBook(blobs, Quarantine(blobs, clock))
        val sub = Subscription(SubscriptionId("s1"), "Поставщик", SubscriptionSource.Url(Secret(URL)), deviceId = DeviceId.generate())
            .copy(metadata = com.dpsmpx.dppass.subscriptions.SubscriptionMetadata(title = "T", traffic = TrafficInfo(1, 2, null, 3)))
        val state = SubscriptionsState(listOf(sub), SubscriptionId("s1"))
        assertTrue(book.save(state).isSuccess)
        assertEquals(state, book.load().valueOrNull())
    }

    @Test
    fun corruptedStateGoesToQuarantineNotOverwritten() {
        val blobs = InMemoryBlobStore()
        blobs.write(SubscriptionBook.KEY, "{\"format\": \"dppass.subscriptions\", \"format_version\": 1, \"items\": [{\"id\": \"BAD ID\"}]}".toByteArray())
        val r = SubscriptionBook(blobs, Quarantine(blobs, clock)).load()
        assertEquals(SubscriptionsState.EMPTY, r.valueOrNull())
        assertTrue(r.diagnostics.any { it.code == DiagCode.STORAGE_CORRUPTED })
        assertTrue(Quarantine(blobs, clock).list().valueOrNull()!!.isNotEmpty(), "исходник не сохранён в карантин")
    }

    @Test
    fun secretsAreNotInPlainTextOnEncryptedStore() {
        val raw = InMemoryBlobStore()
        val store = EncryptingBlobStore(raw, KeyProvider { Outcome.Success(ByteArray(32) { 9 }) })
        val id = DeviceId.generate()
        val sub = Subscription(SubscriptionId("s1"), "S", SubscriptionSource.Url(Secret(URL)), deviceId = id)
        SubscriptionBook(store, Quarantine(store, clock)).save(SubscriptionsState(listOf(sub), null))
        val bytes = String(raw.read(SubscriptionBook.KEY).valueOrNull()!!, Charsets.ISO_8859_1)
        assertFalse("token-0123456789" in bytes || id.reveal() in bytes, "секрет подписки на диске открытым текстом")
    }
}

class SubscriptionFlowTest {
    private val clock = ManualClock(1_000_000)
    private val blobs = InMemoryBlobStore()

    private fun core() = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))

    private class Fetcher(var body: String, var headers: Map<String, String> = emptyMap()) : SubscriptionFetcher {
        val requests = mutableListOf<SubscriptionRequest>()
        override suspend fun fetch(request: SubscriptionRequest, policy: com.dpsmpx.dppass.subscriptions.FetchPolicy) =
            Outcome.Success(FetchedPayload(body.toByteArray(), headers, 0)).also { requests += request }
    }

    private fun added(core: DPpassCore): SubscriptionId = core.subscriptions.add(URL, null).valueOrNull()!!.id

    @Test
    fun refreshAppliesServersWithDefaultPolicyWhenNoUserConfig() = runBlocking {
        val core = core()
        val id = added(core)
        val run = core.subscriptions.refresh(id, Fetcher(Base64.getEncoder().encodeToString(LINKS.toByteArray())), "test").valueOrNull()!!
        assertTrue(run.applied, run.diagnostics.joinToString { it.render() })
        val active = core.activation.state.activeConfig!!
        assertEquals(2, active.profiles.size)
        assertEquals(PolicyBuilder.dns(UserPolicy.DEFAULT), active.dns)
        assertEquals(DnsTransport.Https(DnsProvider.CLOUDFLARE.url), active.dns.servers.single().transport)
        val st = core.subscriptions.state().valueOrNull()!!
        assertEquals(id, st.activeId)
        assertTrue(st.find(id)!!.lastSuccessful != null, "нет удачной ревизии")
    }

    /** Сквозной случай с телефона (6 октября 2026): подписка с повтором ссылки переживает перезапуск. */
    @Test
    fun subscriptionWithRepeatedLinkSurvivesRestart() = runBlocking {
        val core = core()
        val id = added(core)
        val repeated = LINKS + LINKS.lines().first { it.isNotBlank() }.substringBefore('#') + "#Повтор\n"
        val run = core.subscriptions.refresh(id, Fetcher(repeated), "test").valueOrNull()!!
        assertTrue(run.applied, run.diagnostics.joinToString { it.render() })
        assertEquals(2, core.activation.state.activeConfig!!.profiles.size)
        val restarted = core()
        assertTrue(restarted.restore().none { it.code == DiagCode.STORAGE_CORRUPTED }, "состояние читается после перезапуска")
        assertEquals(core.activation.state.activeConfig, restarted.activation.state.activeConfig)
    }

    @Test
    fun userRoutingStaysWhenUserConfigIsActive() = runBlocking {
        val core = core()
        assertIs<ActivationResult.Activated>(core.importAndActivate(java.io.File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()).valueOrNull())
        val userRouting = core.activation.state.activeConfig!!.routing
        val run = core.subscriptions.refresh(added(core), Fetcher(LINKS), "test").valueOrNull()!!
        assertTrue(run.applied)
        assertEquals(userRouting, core.activation.state.activeConfig!!.routing)
    }

    @Test
    fun providerRefusalKeepsLastSuccessfulAndActiveConfig() = runBlocking {
        val core = core()
        val id = added(core)
        val fetcher = Fetcher(LINKS)
        core.subscriptions.refresh(id, fetcher, "test")
        val good = core.subscriptions.state().valueOrNull()!!.find(id)!!.lastSuccessful
        val activeBefore = core.activation.state.active
        fetcher.body = Base64.getEncoder().encodeToString("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?security=none#App%20not%20supported".toByteArray())
        fetcher.headers = mapOf("x-hwid-active" to "true", "x-hwid-not-supported" to "true")
        val run = core.subscriptions.refresh(id, fetcher, "test").valueOrNull()!!
        assertFalse(run.applied)
        assertEquals(DiagCode.SUBSCRIPTION_DEVICE_ID_REQUIRED, run.subscription.lastFailed!!.reason.code)
        assertEquals(good, core.subscriptions.state().valueOrNull()!!.find(id)!!.lastSuccessful)
        assertEquals(activeBefore, core.activation.state.active)
    }

    @Test
    fun deviceIdIsSentOnlyWhenEnabledAndSurvivesRestart() = runBlocking {
        val core = core()
        val id = added(core)
        val fetcher = Fetcher(LINKS)
        core.subscriptions.refresh(id, fetcher, "1.0")
        assertNull(fetcher.requests.last().deviceId)
        assertEquals("DPpass/1.0", fetcher.requests.last().userAgent)

        core.subscriptions.setDeviceId(id, true)
        val first = core.subscriptions.state().valueOrNull()!!.find(id)!!.deviceId!!
        core.subscriptions.refresh(id, fetcher, "1.0")
        assertEquals(first, fetcher.requests.last().deviceId)

        // Новый процесс — тот же идентификатор из хранилища.
        assertEquals(first, core().subscriptions.state().valueOrNull()!!.find(id)!!.deviceId)

        core.subscriptions.resetDeviceId(id)
        assertNotEquals(first, core.subscriptions.state().valueOrNull()!!.find(id)!!.deviceId)
        core.subscriptions.setDeviceId(id, false)
        core.subscriptions.refresh(id, fetcher, "1.0")
        assertNull(fetcher.requests.last().deviceId)
    }

    /** D-38: без своего документа — маршрутизация и DNS политики пользователя. */
    @Test
    fun refreshUsesUserPolicyWhenNoOwnDocument() = runBlocking {
        val core = core()
        core.userPolicy.change(UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true))
        val run = core.subscriptions.refresh(added(core), Fetcher(LINKS), "test").valueOrNull()!!
        assertTrue(run.applied)
        assertEquals(PolicyBuilder.routing(UserPolicy(mode = RoutingMode.RU_DIRECT, blockAds = true)), core.activation.state.activeConfig!!.routing)
    }

    /** D-42: свои серверы — подписка без сети, тот же конвейер и ревизии. */
    @Test
    fun inlineLinksBecomeOwnServers() = runBlocking {
        val core = core()
        val sub = core.subscriptions.addInline(LINKS, "Мои").valueOrNull()!!
        assertIs<SubscriptionSource.Inline>(sub.source)
        assertNull(sub.updatePolicy.intervalMinutes, "своим серверам автообновление не нужно")
        val network = Fetcher("не должно понадобиться")
        val run = core.subscriptions.refresh(sub.id, network, "test").valueOrNull()!!
        assertTrue(run.applied, run.diagnostics.joinToString { it.render() })
        assertTrue(network.requests.isEmpty(), "свои серверы не загружаются по сети")
        assertEquals(2, core.activation.state.activeConfig!!.profiles.size)
        // Переживает перезапуск, тело — секрет и на диске не открытым текстом (хранилище зашифровано на устройстве).
        val again = core().subscriptions.state().valueOrNull()!!.find(sub.id)!!
        assertEquals(sub.source, again.source)
        assertTrue(core.subscriptions.addInline("   ", "x") is Outcome.Failure)
    }

    /** D-39: фоновое обновление — только применённая подписка, по сроку; неизменный сервер не переподключается. */
    @Test
    fun backgroundRefreshKeepsUnchangedConnection() = runBlocking {
        val clock = ManualClock(1_000_000)
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), blobs, clock, "com.dpsmpx.dppass", PlatformTraits(true))
        val id = added(core)
        val fetcher = Fetcher(LINKS)
        assertNull(core.subscriptions.refreshDue(fetcher, "test"), "неприменённая подписка в фоне не обновляется")
        core.subscriptions.refresh(id, fetcher, "test")
        val connected = core.activation.state.activeConfig!!.profiles.first().id
        assertNull(core.subscriptions.refreshDue(fetcher, "test"), "срок не вышел")
        assertEquals(12 * 60 * 60_000L, core.subscriptions.nextDueMillis())

        clock.advance(12 * 60 * 60_000L)
        // Поставщик добавил сервер, подключённый не изменился.
        fetcher.body = LINKS + "vless://00000000-0000-4000-8000-000000000033@203.0.113.33:443?security=tls&sni=c.example.com#C\n"
        val run = core.subscriptions.refreshDue(fetcher, "test")!!.valueOrNull()!!
        assertTrue(run.applied)
        assertEquals(3, core.activation.state.activeConfig!!.profiles.size)
        assertFalse(run.needsReconnect(connected), "подключённый сервер тот же — соединения не рвутся")

        clock.advance(12 * 60 * 60_000L)
        // Подключённого сервера больше нет — переподключение.
        fetcher.body = "trojan://test-password-1@198.51.100.32:443?sni=b.example.com#B\n"
        val gone = core.subscriptions.refreshDue(fetcher, "test")!!.valueOrNull()!!
        assertTrue(gone.needsReconnect(connected))

        // Неизменённое тело — проверка засчитана, срок отодвинут.
        clock.advance(12 * 60 * 60_000L)
        val same = core.subscriptions.refreshDue(fetcher, "test")!!.valueOrNull()!!
        assertIs<UpdateResult.Unchanged>(same.update)
        assertEquals(12 * 60 * 60_000L, core.subscriptions.nextDueMillis())
        // Выключенное автообновление — фона нет.
        core.subscriptions.setUpdateInterval(id, null)
        clock.advance(48 * 60 * 60_000L)
        assertNull(core.subscriptions.refreshDue(fetcher, "test"))
    }

    @Test
    fun namesWithControlCharactersAreRefusedEverywhere() {
        val core = core()
        val subs = core.subscriptions
        for (bad in listOf("две\nстроки", "звонок\u0007", "del\u007f")) {
            assertEquals(DiagCode.NAME_INVALID, subs.add(URL, bad).errors.single().code, bad)
            assertEquals(DiagCode.NAME_INVALID, subs.addInline("свои серверы", bad).errors.single().code, bad)
        }
        assertTrue(subs.state().valueOrNull()!!.items.isEmpty(), "ни одна не сохранена")
        val id = added(core)
        assertEquals(DiagCode.NAME_INVALID, subs.rename(id, "a\tb").errors.single().code)
        assertEquals(DiagCode.NAME_INVALID, subs.rename(id, "   ").errors.single().code)
        assertEquals("sub.example.com", subs.state().valueOrNull()!!.find(id)!!.name, "имя не изменилось")
        // Краевые пробелы — не управляющие символы внутри имени: они убираются.
        assertEquals("Дом", subs.add(URL, "  Дом\t").valueOrNull()!!.name)
    }

    @Test
    fun nameChosenByUserIsRememberedOnAddAndRename() {
        // D-53: имя от пользователя — признак хранения; имя по умолчанию — нет.
        val subs = core().subscriptions
        assertTrue(subs.add(URL, "Дом").valueOrNull()!!.nameByUser)
        assertFalse(subs.add(URL, null).valueOrNull()!!.nameByUser, "имя по хосту — не выбор пользователя")
        assertFalse(subs.add(URL, "   ").valueOrNull()!!.nameByUser, "пустое имя — тоже по хосту")
        assertTrue(subs.addInline("свои серверы", "Мои").valueOrNull()!!.nameByUser)
        val inline = subs.addInline("свои серверы", "").valueOrNull()!!
        assertEquals("DPpass" to false, inline.name to inline.nameByUser)
        val id = subs.add(URL, null).valueOrNull()!!.id
        subs.rename(id, "Работа")
        val renamed = subs.state().valueOrNull()!!.find(id)!!
        assertEquals("Работа" to true, renamed.name to renamed.nameByUser)
        assertEquals("Работа", renamed.displayName)
    }

    @Test
    fun onlyHttpsAddressesAreAccepted() {
        val core = core()
        for (bad in listOf("http://sub.example.com/x", "ftp://sub.example.com", "https://sub.example.com/ x", "https://sub\u0001.example.com/s", "")) {
            assertIs<Outcome.Failure>(core.subscriptions.add(bad, null), bad)
        }
        assertEquals("sub.example.com", core.subscriptions.add(URL, null).valueOrNull()!!.name)
    }
}
