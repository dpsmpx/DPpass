package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.xray.DptsScript
import com.dpsmpx.dppass.engine.xray.DptsInterruption
import com.dpsmpx.dppass.engine.xray.Zapret2GoogleProbe
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DptsLocalSuiteTest {
    private fun row(case: DptsLocalCase) = Zapret2GoogleProbe(
        case.outcome, 0, 0, 10, if (case.method == "plain") 0 else 1, 0)

    @Test fun fixedCasesKeepOrderAndEndpoints() {
        assertEquals(listOf("plain", "http-hostcase", "http-hostows"), DptsLocalSuite.HTTP.cases.map { it.method })
        assertEquals(listOf("local_tls12", "local_tls12", "local_tls12", "local_tls13", "local_tls13", "local_tls13"),
            DptsLocalSuite.TLS.cases.map { it.target })
    }

    @Test fun completeAndInterruptedReportsAreNeverTrainable() {
        for (suite in DptsLocalSuite.entries) {
            val rows = suite.cases.map(::row)
            val full = suite.report(rows)
            assertTrue(full.contains("RUN: completed; training_eligible=false"))
            assertTrue(full.contains("Verified: ${rows.size}/${rows.size}"))
            assertTrue(full.contains("ACCEPTANCE: PASS"))
            for (reason in DptsInterruption.entries) {
                val partial = suite.report(rows.take(1), reason)
                assertTrue(partial.contains("reason=${reason.wire}; training_eligible=false"))
                assertTrue(partial.contains("Verified: 1/${rows.size}"))
                assertTrue(partial.contains("missing=${rows.size - 1}"))
                assertFalse(suite.report(rows, reason).contains("RUN: completed"))
                assertTrue(suite.report(rows, reason).contains("ACCEPTANCE: NOT_VERIFIED"))
            }
            assertTrue(suite.report(emptyList()).contains("Verified: 0/${rows.size}"))
            assertTrue(suite.report(rows + rows.first()).contains("extra=1"))
        }
    }

    @Test fun unexpectedWireMetadataOrCountersNeverVerify() {
        for (suite in DptsLocalSuite.entries) {
            for (case in suite.cases) {
                val good = row(case)
                assertTrue(case.verified(good))
                for (bad in listOf(good.copy(outcome = "ok"), good.copy(httpStatus = 200),
                    good.copy(bodyBytes = 1), good.copy(appliedDelta = good.appliedDelta + 1),
                    good.copy(skippedDelta = 1), good.copy(elapsedMillis = -1),
                    good.copy(dnsFingerprint = "abcdef12"), good.copy(dnsAnswers = 1),
                    good.copy(protocol = "h1"), good.copy(ipIndex = 1),
                    good.copy(tlsStage = "tls_verified"), good.copy(alpn = "h2"))) {
                    assertFalse(case.verified(bad))
                }
            }
        }
    }

    @Test fun combinedPresetHasNineCasesAndCompilerBudgetMatches() {
        val suite = DptsLocalSuite.ACCEPTANCE
        assertEquals(DptsLocalSuite.HTTP.cases + DptsLocalSuite.TLS.cases, suite.cases)
        assertEquals(9, suite.cases.size)
        for ((id, local) in listOf("local_http_hostcase" to DptsLocalSuite.HTTP,
            "local_tls" to DptsLocalSuite.TLS, "local_acceptance" to suite)) {
            val plan = DptsScript.compile("dpts 1\nhost example.com\nlearn off\nsuite $id")
            assertEquals(local.budgetMs, plan.budgetMs)
            assertFalse(plan.observeLearning)
        }
        val rows = suite.cases.map(::row)
        val report = suite.report(rows)
        for (part in listOf("HTTP: 3/3", "TLS 1.2: 3/3", "TLS 1.3: 3/3", "ACCEPTANCE: PASS")) {
            assertTrue(report.contains(part))
        }
        for (invalid in listOf(rows.dropLast(1), rows + rows.first(),
            listOf(rows.first().copy(skippedDelta = 1)) + rows.drop(1))) {
            assertTrue(suite.report(invalid).contains("ACCEPTANCE: NOT_VERIFIED"))
        }
    }
}
