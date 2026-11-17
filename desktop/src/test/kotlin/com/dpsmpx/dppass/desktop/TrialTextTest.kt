package com.dpsmpx.dppass.desktop

import com.dpsmpx.dppass.connection.TrialReport
import com.dpsmpx.dppass.connection.TrialSummary
import com.dpsmpx.dppass.desktop.ui.TrialText
import com.dpsmpx.dppass.diagnostics.DiagCode
import kotlin.test.Test
import kotlin.test.assertEquals

/** Итог замера А/Б на ПК (D-117): как на телефоне — успехи, медиана, отказы и «без приёма» не теряются. */
class TrialTextTest {
    @Test
    fun linesKeepEveryFact() {
        val report = TrialReport(
            emptyList(),
            listOf(
                TrialSummary("plain", 9, 10, 420, mapOf(DiagCode.ENDPOINT_UNREACHABLE to 1), 0),
                TrialSummary("fake-5", 0, 10, null, mapOf(DiagCode.HEALTH_CHECK_FAILED to 10), 2),
                TrialSummary("disorder", 10, 10, 380, emptyMap(), 0),
            ),
        )
        assertEquals(
            "Без приёма — прошло: 9/10 · медиана 420 мс · ENDPOINT_UNREACHABLE×1\n" +
                "Подделка, TTL 5 — прошло: 0/10 · HEALTH_CHECK_FAILED×10 · без приёма 2×\n" +
                "Перестановка (TTL 1) — прошло: 10/10 · медиана 380 мс",
            TrialText.report(report),
        )
    }
}
