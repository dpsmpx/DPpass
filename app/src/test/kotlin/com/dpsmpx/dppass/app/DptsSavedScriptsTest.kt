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

    @Test fun restorationIsTypedBoundedAndDeterministic() {
        val values = (0..34).reversed().associate { "script.draft%02d".format(it) to "draft" }
        val mixed = values + mapOf("script.!" to 1, "script." to "bad", "other" to "ignored")
        val restored = DptsSavedScripts.restore(mixed)
        assertEquals(DptsSavedScripts.MAX_SCRIPTS, restored.size)
        assertEquals((0..29).map { "draft%02d".format(it) }, restored.keys.toList())
        assertEquals(restored, DptsSavedScripts.restore(mixed.toList().reversed().toMap()))
    }
}
