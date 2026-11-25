package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsSavedScriptsTest {
    @Test fun draftAdmissionMatchesRestoreAndAllowsUncompiledText() {
        val source = "unfinished draft"
        val names = listOf("", " ", " padded", "padded ", "a\nb", "a\u007fb",
            "a\u202eb", "a\u2028b", "a".repeat(81))
        for (name in names) {
            assertFalse(DptsSavedScripts.validDraft(name, source))
            assertTrue(DptsSavedScripts.restore(mapOf("script.$name" to source)).isEmpty())
        }
        for (name in listOf("Мой черновик", "日本語", "a".repeat(80))) {
            assertTrue(DptsSavedScripts.validDraft(name, source))
            assertEquals(mapOf(name to source),
                DptsSavedScripts.restore(mapOf("script.$name" to source)))
        }
        for (invalid in listOf("", " \n", "x".repeat(DptsScript.MAX_SOURCE_LENGTH + 1))) {
            assertFalse(DptsSavedScripts.validDraft("name", invalid))
            assertTrue(DptsSavedScripts.restore(mapOf("script.name" to invalid)).isEmpty())
        }
        assertTrue(DptsSavedScripts.validDraft("name", "x".repeat(DptsScript.MAX_SOURCE_LENGTH)))
    }

    @Test fun catalogIdentityDoesNotDependOnDisplayPrefixOrNameCollisions() {
        val builtIn = linkedMapOf("Shared" to "builtin", "Мой: Shared" to "other builtin")
        val personal = linkedMapOf("Shared" to "personal", "A" to "draft")
        val entries = DptsSavedScripts.catalog(builtIn, personal)
        val builtinId = DptsSavedScripts.ScriptId("Shared", false)
        val personalId = DptsSavedScripts.ScriptId("Shared", true)
        assertEquals(listOf(builtinId, DptsSavedScripts.ScriptId("Мой: Shared", false),
            DptsSavedScripts.ScriptId("A", true), personalId), entries.map { it.id })
        assertEquals("builtin", entries.single { it.id == builtinId }.source)
        assertEquals("personal", entries.single { it.id == personalId }.source)
    }

    @Test fun editorRestorePreservesEmptyAndIncompleteDraftsWithoutTruncation() {
        val fallback = "default"
        assertEquals("", DptsSavedScripts.restoreEditor("", fallback))
        assertEquals("unfinished", DptsSavedScripts.restoreEditor("unfinished", fallback))
        val max = "x".repeat(DptsScript.MAX_SOURCE_LENGTH)
        assertEquals(max, DptsSavedScripts.restoreEditor(max, fallback))
        for (invalid in listOf(null, 42, true, max + "x")) {
            assertEquals(fallback, DptsSavedScripts.restoreEditor(invalid, fallback))
        }
    }

    @Test fun editorNameRestoresUnfinishedNamesWithoutCoercingInvalidValues() {
        assertEquals(" unfinished ", DptsSavedScripts.restoreEditorName(" unfinished "))
        assertEquals("日本語", DptsSavedScripts.restoreEditorName("日本語"))
        assertEquals("x".repeat(80), DptsSavedScripts.restoreEditorName("x".repeat(80)))
        for (invalid in listOf(null, 42, "a\nb", "a\u202eb", "x".repeat(81))) {
            assertEquals("", DptsSavedScripts.restoreEditorName(invalid))
        }
    }

    @Test fun onlyValidPersonalIdentityCanAddressSavedPreference() {
        assertEquals("script.Shared", DptsSavedScripts.preferenceKey(
            DptsSavedScripts.ScriptId("Shared", true)))
        assertEquals(null, DptsSavedScripts.preferenceKey(
            DptsSavedScripts.ScriptId("Shared", false)))
        assertEquals(null, DptsSavedScripts.preferenceKey(
            DptsSavedScripts.ScriptId("bad\nname", true)))
        assertEquals(null, DptsSavedScripts.preferenceKey(
            DptsSavedScripts.ScriptId("", true)))
    }

    @Test fun restorationIsTypedBoundedAndDeterministic() {
        val values = (0..34).reversed().associate { "script.draft%02d".format(it) to "draft" }
        val mixed = values + mapOf("script.!" to 1, "script." to "bad", "other" to "ignored")
        val restored = DptsSavedScripts.restore(mixed)
        assertEquals(DptsSavedScripts.MAX_SCRIPTS, restored.size)
        assertEquals((0..29).map { "draft%02d".format(it) }, restored.keys.toList())
        assertEquals(restored, DptsSavedScripts.restore(mixed.toList().reversed().toMap()))
    }
}
