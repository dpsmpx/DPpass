package com.dpsmpx.dppass.app.paths

import com.dpsmpx.dppass.app.AppPrefs
import com.dpsmpx.dppass.app.ServerAutoContext
import com.dpsmpx.dppass.app.ServerAutoMode
import com.dpsmpx.dppass.app.ServerAutoModel
import com.dpsmpx.dppass.app.Zapret2NeuralModel
import com.dpsmpx.dppass.connection.ActivationResult
import com.dpsmpx.dppass.connection.ConnectionReport
import com.dpsmpx.dppass.connection.DPpassCore
import com.dpsmpx.dppass.connection.HealthChecker
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.LogEvent
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.network.NetworkType
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import java.io.File
import kotlinx.coroutines.runBlocking
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.annotation.Config
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [26, 29, 36], manifest = Config.NONE)
class ServerAutoModeTest {
    private val context = RuntimeEnvironment.getApplication()
    private val modelKind = Zapret2NeuralModel.Kind.SERVER
    private val wifiTcp = ServerAutoContext.WIFI_TCP.ordinal

    @Test fun compareWithTheSameWeightsAndResumeTraining() = runBlocking {
        val prefs = AppPrefs(context)
        assertEquals(ServerAutoMode.ADAPTIVE, prefs.serverAutoMode)
        assertEquals(ServerAutoMode.ADAPTIVE, ServerAutoMode.fromPreference("unknown"))

        val missing = connect(ServerAutoMode.FROZEN, modelAvailable = false)
        assertEquals("false", missing.fields["model_scored"])
        assertEquals("null", missing.fields["observations_before"])
        assertEquals("0", missing.fields["attempted_moved"])
        assertNull(Zapret2NeuralModel.readVerified(context, modelKind))

        val snapshot = fixedModel()
        assertTrue(Zapret2NeuralModel.store(context, modelKind, snapshot))

        val planner = connect(ServerAutoMode.PLANNER)
        assertEquals("false", planner.fields["model_scored"])
        assertEquals("0", planner.fields["attempted_moved"])
        assertContentEquals(snapshot, Zapret2NeuralModel.readVerified(context, modelKind))

        val frozen = connect(ServerAutoMode.FROZEN)
        assertEquals("true", frozen.fields["model_scored"])
        assertEquals("4", frozen.fields["observations_before"])
        assertEquals("2", frozen.fields["attempted_moved"])
        assertContentEquals(snapshot, Zapret2NeuralModel.readVerified(context, modelKind))

        val adaptive = connect(ServerAutoMode.ADAPTIVE)
        assertEquals(frozen.fields, adaptive.fields)
        val updated = JSONObject(checkNotNull(Zapret2NeuralModel.readVerified(context, modelKind)).decodeToString())
        assertEquals(6, updated.getJSONArray("context_observations").getInt(wifiTcp))
    }

    private suspend fun connect(mode: ServerAutoMode, modelAvailable: Boolean = true): LogEvent {
        AppPrefs(context).serverAutoMode = mode
        val configuredMode = AppPrefs(context).serverAutoMode
        assertEquals(mode, configuredMode)
        val sink = MemoryLogSink()
        val core = DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), ManualClock(1000),
            "com.dpsmpx.dppass", PlatformTraits(true), sink)
        assertIs<ActivationResult.Activated>(core.importAndActivate(config()).valueOrNull())
        val initialOrder = checkNotNull(core.plan(null)).attempts.map { it.profile.id }
        val expectedOrder = if (configuredMode == ServerAutoMode.PLANNER || !modelAvailable) initialOrder else initialOrder.reversed()
        val checker = HealthChecker { _, profile ->
            if (profile.id == expectedOrder.first()) Outcome.failure(DiagCode.ENDPOINT_UNREACHABLE, "синтетический отказ")
            else Outcome.Success(Unit)
        }
        val token = ServerAutoModel.beginLearning()
        try {
            val report = assertIs<ConnectionReport.Connected>(core.connect(null, checker, null, rerank = { plan ->
                ServerAutoModel.rerank(context, plan, core, NetworkType.WIFI, core.clock.nowMillis(), token, configuredMode)
            }) {})
            try {
                assertEquals(expectedOrder, report.attempts.map { it.profileId })
                ServerAutoModel.observe(context, report, core, token)
            } finally {
                report.session.stop()
            }
            assertEquals(configuredMode.name, sink.snapshot().single { it.event == "server_auto_model" }.fields["mode"])
            assertEquals((modelAvailable && mode == ServerAutoMode.ADAPTIVE).toString(),
                sink.snapshot().single { it.event == "server_auto_learning" }.fields["persisted"])
            return sink.snapshot().single { it.event == "server_auto_outcome" }
        } finally {
            ServerAutoModel.finishLearning(token)
        }
    }

    private fun config(): String {
        val fixture = generateSequence(File(".").absoluteFile) { it.parentFile }
            .map { it.resolve("tests/data/configs/valid-multi.json") }.first { it.isFile }
        val document = JSONObject(fixture.readText())
        val profile = document.getJSONArray("profiles").getJSONObject(0).toString()
        val profiles = JSONArray()
            .put(JSONObject(profile).put("id", "test-a"))
            .put(JSONObject(profile).put("id", "test-b").put("server", "203.0.113.11"))
        return document.put("profiles", profiles).toString()
    }

    /** Первый нейрон передаёт обратный ранг, отрицательный вес поднимает второго кандидата. */
    private fun fixedModel(): ByteArray {
        val model = JSONObject(Zapret2NeuralModel.build(modelKind, 32).decodeToString())
        val hidden = model.getJSONArray("hidden").getJSONArray(0)
        repeat(hidden.length()) { index -> hidden.put(index, if (index == 7) 1.0 else 0.0) }
        val output = model.getJSONArray("output").getJSONArray(wifiTcp)
        repeat(output.length()) { index -> output.put(index, if (index == 0) -4.0 else 0.0) }
        model.getJSONArray("context_observations").put(wifiTcp, 4)
        return model.put("observations", 4).toString().encodeToByteArray()
    }
}
