package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.desktop.ui.SplitSitesDialog
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Outcome
import com.dpsmpx.dppass.routing.SplitSites
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/** Правка списка «Напрямую с разбиением» на ПК (D-82): неверная строка или неизвестный geosite — отказ целиком (D-05). */
class SplitSitesDialogTest {
    private val known: (SplitSites) -> List<Diagnostic> = { s ->
        s.geoSites.filter { it != "youtube" }.map { Diagnostic.error(DiagCode.GEO_CODE_UNKNOWN, "нет списка geosite:$it в наборе") }
    }

    @Test
    fun validListIsAccepted() {
        val text = "# мои\nExample.com\n*.Video.example\ngeosite:youtube\n"
        val r = assertIs<Outcome.Success<SplitSites>>(SplitSitesDialog.validate(text, known))
        assertEquals(listOf("example.com", "video.example"), r.value.domains)
        assertEquals(listOf("youtube"), r.value.geoSites)
    }

    @Test
    fun badLineIsRefusedWithItsNumber() {
        val r = assertIs<Outcome.Failure>(SplitSitesDialog.validate("example.com\nне домен", known))
        assertTrue("строка 2" in r.errors.first().message, r.errors.first().message)
    }

    @Test
    fun unknownGeositeIsRefusedByTheCoreSet() {
        val r = assertIs<Outcome.Failure>(SplitSitesDialog.validate("geosite:nonexistent", known))
        assertEquals(DiagCode.GEO_CODE_UNKNOWN, r.errors.first().code)
    }
}
