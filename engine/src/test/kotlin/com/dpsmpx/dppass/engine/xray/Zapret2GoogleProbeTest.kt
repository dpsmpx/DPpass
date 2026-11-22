package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2GoogleProbeTest {
    @Test fun exactStrategiesAndNativeTags() {
        assertEquals(8, Zapret2ProbeCatalog.strategies.size)
        assertEquals("dppass:test-plain", Zapret2ProbeCatalog.tag("plain"))
        assertEquals("dppass:test-tlsrec-split", Zapret2ProbeCatalog.tag("tlsrec-split"))
        assertEquals("dppass:exp-tlsrec-split", Zapret2ProbeCatalog.experimentTag("tlsrec-split"))
        assertEquals(null, Zapret2ProbeCatalog.tag("fake-9"))
    }

    @Test fun validHttpResponseRequiresVersionedCompleteWire() {
        val ok = Zapret2GoogleProbe.fromWire("v1\tok\t200\t8192\t300\t1\t0".encodeToByteArray())
        assertTrue(ok.success)
        assertEquals(200, ok.httpStatus)
        assertEquals(8192, ok.bodyBytes)
        assertTrue(Zapret2GoogleProbe.fromWire("v1\tredirect\t301\t0\t100\t0\t0".encodeToByteArray()).success)
        assertFalse(Zapret2GoogleProbe.fromWire("v1\ttls_failed\t0\t0\t100\t0\t0".encodeToByteArray()).success)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire("v2\tok\t200".encodeToByteArray()).outcome)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire("v1\tok\t200\t-2\t0\t0\t0".encodeToByteArray()).outcome)
    }

    @Test fun medianOfTwoUsesBothTimesAndPreservesHalfMilliseconds() {
        assertEquals("-", Zapret2GoogleReport.medianMillis(emptyList()))
        assertEquals("275", Zapret2GoogleReport.medianMillis(listOf(275)))
        assertEquals("301", Zapret2GoogleReport.medianMillis(listOf(335, 267)))
        assertEquals("300.5", Zapret2GoogleReport.medianMillis(listOf(323, 278)))
        assertEquals("458.5", Zapret2GoogleReport.medianMillis(listOf(489, 428)))
        assertEquals("270", Zapret2GoogleReport.medianMillis(listOf(275, 265)))
        assertEquals("300", Zapret2GoogleReport.medianMillis(listOf(100, 1000, 300)))
        assertEquals("400", Zapret2GoogleReport.medianMillis(listOf(100, 300, 500, 700)))
    }

    @Test fun completeReportIncludesFailuresAndWarnsAboutGoogleVsYoutube() {
        val attempts = listOf(
            Zapret2GoogleAttempt("plain", 1, Zapret2GoogleProbe.fromWire(
                "v1\tok\t200\t8000\t100\t0\t0".encodeToByteArray())),
            Zapret2GoogleAttempt("fake-5", 1, Zapret2GoogleProbe.fromWire(
                "v1\ttls_failed\t0\t0\t8000\t1\t0".encodeToByteArray())),
        )
        val report = Zapret2GoogleReport.render("2026-11-22T21:00:00+03:00", "MOBILE", false, attempts)
        assertTrue(report.contains("Target: https://google.com/"))
        assertTrue(report.contains("plain: 1/1 HTTP replies"))
        assertTrue(report.contains("fake-5: 0/1 HTTP replies"))
        assertTrue(report.contains("outcome=tls_failed"))
        assertTrue(report.contains("does not prove YouTube"))
        assertTrue(report.contains("Scope: TCP/HTTPS"))
    }
}
