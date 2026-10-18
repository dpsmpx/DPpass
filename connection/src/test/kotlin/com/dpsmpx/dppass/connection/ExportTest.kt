package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.ConfigWriter
import com.dpsmpx.dppass.config.LoadedConfig
import com.dpsmpx.dppass.core.ManualClock
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.engine.mock.MockBackendCompiler
import com.dpsmpx.dppass.engine.mock.MockProxyEngine
import com.dpsmpx.dppass.storage.InMemoryBlobStore
import com.dpsmpx.dppass.tunnel.PlatformTraits
import kotlinx.coroutines.runBlocking
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Экспорт активной конфигурации (D-11): без секретов — по умолчанию и не активируется; с секретами — тот же документ. */
class ExportTest {
    private fun core() =
        DPpassCore(MockBackendCompiler(), MockProxyEngine(), InMemoryBlobStore(), ManualClock(1_000), "com.dpsmpx.dppass", PlatformTraits(true))

    @Test
    fun exportIsRedactedByDefaultAndOnlyTheFullOneActivatesAgain() = runBlocking {
        val core = core()
        assertNull(core.export(), "активной нет — экспортировать нечего")
        val source = File(System.getProperty("dppass.repoRoot"), "tests/data/configs/valid-minimal.json").readText()
        assertIs<ActivationResult.Activated>(core.importAndActivate(source).valueOrNull())

        val redacted = core.export()!!
        assertTrue(Secret.REDACTED in redacted, redacted)
        // Синтетический UUID и short_id документа корпуса — их в экспорте без секретов нет.
        assertFalse("00000000-0000-4000-8000-000000000001" in redacted)
        assertFalse("01234567" in redacted)
        assertIs<Outcome.Failure>(core.load(redacted), "документ без секретов не активируется (D-11)")

        val full = core.export(ConfigWriter.Mode.FULL)!!
        val again = assertIs<Outcome.Success<LoadedConfig>>(core.load(full)).value.ir
        assertEquals(core.activation.state.activeConfig!!.profiles, again.profiles)
    }
}
