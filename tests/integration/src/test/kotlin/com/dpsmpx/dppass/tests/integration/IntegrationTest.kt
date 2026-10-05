package com.dpsmpx.dppass.tests.integration

import com.dpsmpx.dppass.config.ConfigLoader
import com.dpsmpx.dppass.config.ConfigWriter
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.SimulatedHealthChecker
import com.dpsmpx.dppass.connection.toTunInput
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.core.SubscriptionId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.mock.MockBackend
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockBehavior
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.network.NetworkAssessor
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.network.ProbeBudget
import com.dpsmpx.dppass.network.simulation.NetworkCondition
import com.dpsmpx.dppass.network.simulation.SimulatedNetwork
import com.dpsmpx.dppass.routing.RouteAction
import com.dpsmpx.dppass.routing.RouteQuery
import com.dpsmpx.dppass.storage.EncryptingBlobStore
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.storage.KeyProvider
import com.dpsmpx.dppass.storage.KeyWrapper
import com.dpsmpx.dppass.storage.StorageReset
import com.dpsmpx.dppass.storage.WrappedKeyProvider
import com.dpsmpx.dppass.subscriptions.FetchedPayload
import com.dpsmpx.dppass.subscriptions.Subscription
import com.dpsmpx.dppass.subscriptions.SubscriptionFetcher
import com.dpsmpx.dppass.subscriptions.SubscriptionSource
import com.dpsmpx.dppass.subscriptions.SubscriptionUpdater
import com.dpsmpx.dppass.subscriptions.UpdateResult
import com.dpsmpx.dppass.tunnel.FakeTunnelProvider
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

private val root = File(System.getProperty("dppass.repoRoot"))
private fun data(p: String) = File(root, "tests/data/$p").readText()

private class Env(val engine: MockProxyEngine = MockProxyEngine(), val blobs: InMemoryBlobStore = InMemoryBlobStore()) {
    val clock = ManualClock(1_000_000)
    val sink = MemoryLogSink(4096)
    val store = EncryptingBlobStore(blobs, KeyProvider { Outcome.Success(ByteArray(32) { 7 }) })
    val core = DPpassCore(MockBackendCompiler(engine.capabilities), engine, store, clock, "com.dpsmpx.dppass", PlatformTraits(true), sink)

    fun assess(c: NetworkCondition, net: SimulatedNetwork = SimulatedNetwork(c)) =
        runBlocking { NetworkAssessor(net, ProbeBudget(clock)) { clock.advance(it) }.assess(NetworkType.MOBILE) }
}

class ConfigToActiveProfileTest {
    @Test
    fun documentBecomesActiveAndConnects() = runBlocking {
        val env = Env()
        val r = env.core.importAndActivate(data("configs/valid-multi.json")).valueOrNull()
        assertIs<ActivationResult.Activated>(r)
        assertEquals(RouteAction.BLOCK, env.core.explain(RouteQuery(domain = "ads.example.com"))!!.action)

        val tun = FakeTunnelProvider()
        val handle = tun.establish(env.core.tunnelSpec()!!.valueOrNull()!!).valueOrNull()!!
        val net = SimulatedNetwork(NetworkCondition.NORMAL)
        val report = env.core.connect(env.assess(NetworkCondition.NORMAL, net), SimulatedHealthChecker(net), handle.toTunInput()) { env.clock.advance(it) }
        val connected = assertIs<ConnectionReport.Connected>(report)
        assertEquals(listOf(connected.profileId.value), env.engine.startedProfiles)
    }
}

class SubscriptionActivationTest {
    private fun fetcher(body: String, clock: ManualClock) =
        SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(body.toByteArray(), emptyMap(), clock.nowMillis())) }

    @Test
    fun subscriptionUpdateActivatesAtomicallyAndBadUpdateKeepsOld() = runBlocking {
        val env = Env()
        val base = ConfigLoader().load(data("configs/valid-minimal.json")).valueOrNull()!!.ir
        var sub = Subscription(SubscriptionId("prov"), "Provider", SubscriptionSource.Url(Secret("https://sub.example.com/abc")))

        val first = SubscriptionUpdater(fetcher(data("subscriptions/links-plain.txt"), env.clock), env.clock).update(sub, env.core.profileFilter())
        val (afterFirst, act) = env.core.activateSubscription(base, (first as UpdateResult.Ready).candidate)
        assertIs<ActivationResult.Activated>(act)
        sub = afterFirst
        assertEquals(1, sub.lastSuccessful!!.number)
        assertEquals(3, env.core.activation.state.activeConfig!!.profiles.size)
        // маршрутизация — пользователя, не поставщика
        assertEquals(base.routing, env.core.activation.state.activeConfig!!.routing)

        val bad = SubscriptionUpdater(fetcher(data("subscriptions/garbage.txt"), env.clock), env.clock).update(sub, env.core.profileFilter())
        val failed = assertIs<UpdateResult.Failed>(bad)
        assertEquals(sub.lastSuccessful, failed.subscription.lastSuccessful)
        assertEquals(3, env.core.activation.state.activeConfig!!.profiles.size, "действующая конфигурация не тронута")
    }

    @Test
    fun engineRejectionDoesNotAdvanceSubscription() = runBlocking {
        val env = Env(MockProxyEngine(behavior = MockBehavior(rejectConfig = true)))
        val base = ConfigLoader().load(data("configs/valid-minimal.json")).valueOrNull()!!.ir
        val sub = Subscription(SubscriptionId("prov"), "Provider", SubscriptionSource.Url(Secret("https://sub.example.com/abc")))
        val ready = SubscriptionUpdater(fetcher(data("subscriptions/links-plain.txt"), env.clock), env.clock).update(sub, env.core.profileFilter()) as UpdateResult.Ready
        val (after, act) = env.core.activateSubscription(base, ready.candidate)
        assertIs<ActivationResult.Rejected>(act)
        assertEquals(null, after.lastSuccessful)
        assertEquals(DiagCode.ACTIVATION_REJECTED, after.lastFailed!!.reason.code)
    }
}

class RollbackTest {
    @Test
    fun runtimeFailureRollsBackToLastKnownGood() = runBlocking {
        val env = Env()
        env.core.importAndActivate(data("configs/valid-minimal.json"))
        env.core.importAndActivate(data("configs/valid-multi.json"))
        val net = SimulatedNetwork(NetworkCondition.FULL_ENDPOINT_BLOCK)
        val report = env.core.connect(env.assess(NetworkCondition.FULL_ENDPOINT_BLOCK, net), SimulatedHealthChecker(net), null) { env.clock.advance(it) }
        val failed = assertIs<ConnectionReport.Failed>(report)
        val r = env.core.activation.rollback(failed.reason)
        assertTrue(r.isSuccess)
        assertEquals(DiagCode.ROLLED_BACK_TO_LAST_KNOWN_GOOD, r.diagnostics.single().code)
        assertEquals(1, env.core.activation.state.activeConfig!!.profiles.size)
    }
}

class BackendLifecycleTest {
    @Test
    fun startFailureOnOneCandidateMovesToNext() = runBlocking {
        val engine = MockProxyEngine(behavior = MockBehavior(failStart = true))
        val env = Env(engine)
        env.core.importAndActivate(data("configs/valid-multi.json"))
        val net = SimulatedNetwork(NetworkCondition.NORMAL)
        val report = env.core.connect(env.assess(NetworkCondition.NORMAL, net), SimulatedHealthChecker(net), null) { env.clock.advance(it) }
        val failed = assertIs<ConnectionReport.Failed>(report)
        assertTrue(failed.attempts.all { it.failure?.code == DiagCode.BACKEND_START_FAILED })
    }

    @Test
    fun limitedBackendFiltersSubscriptionServersExplicitly() = runBlocking {
        val env = Env(MockProxyEngine(MockBackend.LIMITED))
        val sub = Subscription(SubscriptionId("prov"), "Provider", SubscriptionSource.Url(Secret("https://sub.example.com/abc")))
        val f = SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(data("subscriptions/links-plain.txt").toByteArray(), emptyMap(), 0)) }
        val r = SubscriptionUpdater(f, env.clock).update(sub, env.core.profileFilter()) as UpdateResult.Ready
        assertEquals(2, r.candidate.profiles.size)
        assertTrue(r.diagnostics.any { it.code == DiagCode.PROFILE_EXCLUDED_UNSUPPORTED })
    }
}

/**
 * Свойство безопасности (D-11): после полного прохода конвейера с
 * известными секретами ни журнал, ни находки, ни отчёт, ни `toString()`
 * объектов, ни хранилище на «диске» не содержат секретов открытым текстом.
 */
class SecretLeakTest {
    private val secrets = listOf(
        "00000000-0000-4000-8000-000000000001", "00000000-0000-4000-8000-000000000011",
        "test-password-1", "test-password-2", "test-password-3", "test-obfs-1", "https://sub.example.com/abc",
    )

    @Test
    fun noSecretsInLogsReportsDiagnosticsOrDisk() = runBlocking {
        val env = Env(MockProxyEngine(behavior = MockBehavior(rejectConfig = false)))
        val texts = mutableListOf<String>()
        val r1 = env.core.importAndActivate(data("configs/valid-multi.json"))
        texts += r1.diagnostics.map(Diagnostic::render)
        texts += r1.valueOrNull().toString()
        texts += env.core.activation.state.toString()
        texts += env.core.activation.state.activeConfig.toString()

        val sub = Subscription(SubscriptionId("prov"), "Provider", SubscriptionSource.Url(Secret("https://sub.example.com/abc")))
        val f = SubscriptionFetcher { _, _ -> Outcome.Success(FetchedPayload(data("subscriptions/links-with-directives.txt").toByteArray(), emptyMap(), 0)) }
        val u = SubscriptionUpdater(f, env.clock).update(sub, env.core.profileFilter())
        texts += u.diagnostics.map(Diagnostic::render)
        texts += u.toString()

        val bad = env.core.importAndActivate(data("configs/invalid-reality-key.json"))
        texts += bad.diagnostics.map(Diagnostic::render)

        val net = SimulatedNetwork(NetworkCondition.TLS_DEGRADED)
        val report = env.core.connect(env.assess(NetworkCondition.TLS_DEGRADED, net), SimulatedHealthChecker(net), null) { env.clock.advance(it) }
        texts += report.toString()
        texts += env.sink.snapshot().map { it.render() }
        texts += env.core.report(r1.diagnostics).render()
        texts += ConfigWriter.write(env.core.activation.state.activeConfig!!)
        texts += env.blobs.rawSnapshot().values.map { String(it, Charsets.ISO_8859_1) }

        for (t in texts) for (s in secrets) assertFalse(s in t, "утечка «$s» в: ${t.take(200)}")
    }
}

/** Keystore на хосте: AES-GCM в памяти; ключ можно «утратить». */
private class HostKeyWrapper : KeyWrapper {
    var kek: SecretKey? = null

    override fun exists(): Boolean = kek != null

    override fun create() {
        if (kek == null) kek = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
    }

    override fun wrap(plain: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run { init(Cipher.ENCRYPT_MODE, kek); iv + doFinal(plain) }

    override fun unwrap(sealed: ByteArray): ByteArray =
        Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, kek, GCMParameterSpec(128, sealed, 0, 12))
            doFinal(sealed, 12, sealed.size - 12)
        }
}

/** Утрата ключа хранилища (D-19): ничего не затирается молча; сброс — действием пользователя, без потери. */
class StorageKeyLossTest {
    private val clock = ManualClock(1_000_000)
    private val data = InMemoryBlobStore()
    private val keys = InMemoryBlobStore()
    private val wrapper = HostKeyWrapper()

    /** Новый процесс: ключ данных заново читается с «диска». */
    private fun core(): DPpassCore {
        val provider = WrappedKeyProvider(keys, wrapper, dataPresent = { StorageReset.hasData(data) })
        val engine = MockProxyEngine()
        return DPpassCore(
            MockBackendCompiler(engine.capabilities), engine, EncryptingBlobStore(data, provider), clock, "com.dpsmpx.dppass",
            PlatformTraits(true), storageRecovery = StorageReset(data, provider, clock),
        )
    }

    @Test
    fun lostKeyBlocksWritesUntilExplicitResetThatKeepsEverything() = runBlocking {
        val first = core()
        assertTrue(first.restore().isEmpty())
        assertIs<ActivationResult.Activated>(first.importAndActivate(data("configs/valid-multi.json")).valueOrNull())
        val stored = data.rawSnapshot()

        wrapper.kek = null // ключ Keystore утрачен
        val after = core()
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, after.restore().single().code)
        val r = assertIs<ActivationResult.Rejected>(after.importAndActivate(data("configs/valid-minimal.json")).valueOrNull())
        assertEquals(DiagCode.STORAGE_DATA_KEY_LOST, r.diagnostics.first().causes.single().code)
        assertEquals(stored.keys, data.rawSnapshot().keys, "ничего не записано и не удалено")

        val moved = after.resetStorage()
        val where = moved.valueOrNull()!!
        assertTrue(moved.diagnostics.isEmpty(), "после сброса состояние читается: пустое")
        stored.forEach { (k, v) -> assertTrue(v.contentEquals(data.rawSnapshot().getValue("$where/$k")), "отложено как есть: $k") }
        assertIs<ActivationResult.Activated>(after.importAndActivate(data("configs/valid-minimal.json")).valueOrNull())
        val restarted = core()
        assertTrue(restarted.restore().isEmpty(), "после перезапуска новым ключом всё читается")
        assertEquals(1, restarted.activation.state.activeConfig!!.profiles.size)
    }

    @Test
    fun shellWithoutRecoveryCannotResetSilently() {
        assertEquals(DiagCode.INTERNAL_ERROR, Env().core.resetStorage().errors.single().code)
    }
}

class EngineReportTest {
    @Test
    fun reportShowsWhatTheShellKnowsAboutTheEngine() {
        // D-27: из чего собран набор геоданных — в локальном отчёте, рядом с версией ядра.
        val engine = MockProxyEngine()
        val core = DPpassCore(
            MockBackendCompiler(engine.capabilities), engine, InMemoryBlobStore(), ManualClock(0), "com.dpsmpx.dppass",
            PlatformTraits(true), engineDetails = listOf("geodata" to "dlc 0123456789ab, DB-IP 2026-01"),
        )
        val text = core.report().render()
        assertTrue("geodata: dlc 0123456789ab, DB-IP 2026-01" in text, text)
    }
}
