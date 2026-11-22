package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2GoogleProbeTest {
    @Test fun completeStrategyAndDestinationCatalogs() {
        assertEquals(8, Zapret2ProbeCatalog.strategies.size)
        assertEquals(listOf("google_final", "youtube_home", "youtube_thumbnail"),
            Zapret2ProbeCatalog.targets)
        assertEquals("dppass:test-plain", Zapret2ProbeCatalog.tag("plain"))
        assertEquals("dppass:test-tlsrec-split", Zapret2ProbeCatalog.tag("tlsrec-split"))
        assertEquals("dppass:exp-tlsrec-split", Zapret2ProbeCatalog.experimentTag("tlsrec-split"))
        assertEquals(null, Zapret2ProbeCatalog.tag("fake-9"))
    }

    @Test fun httpRedirectIsTransportReplyNotContentSuccess() {
        val ok = Zapret2GoogleProbe.fromWire("v1\tok\t200\t8192\t300\t1\t0".encodeToByteArray())
        assertTrue(ok.success)
        assertEquals(200, ok.httpStatus)
        assertEquals(8192, ok.bodyBytes)
        assertFalse(Zapret2GoogleProbe.fromWire("v1\tredirect\t301\t220\t100\t0\t0".encodeToByteArray()).success)
        assertFalse(Zapret2GoogleProbe.fromWire("v1\tcontent_invalid\t200\t220\t100\t1\t0".encodeToByteArray()).success)
        assertFalse(Zapret2GoogleProbe.fromWire("v1\ttls_failed\t0\t0\t100\t0\t0".encodeToByteArray()).success)
    }

    @Test fun contractRejectsBadVersionAndNumbers() {
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire("v2\tok\t200".encodeToByteArray()).outcome)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire("v1\tok\t200\t-2\t0\t0\t0".encodeToByteArray()).outcome)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire("v1\tuntrusted\t200\t20\t0\t0\t0".encodeToByteArray()).outcome)
    }

    @Test fun medianOfTwoPreservesHalfMilliseconds() {
        assertEquals("-", Zapret2GoogleReport.medianMillis(emptyList()))
        assertEquals("275", Zapret2GoogleReport.medianMillis(listOf(275)))
        assertEquals("301", Zapret2GoogleReport.medianMillis(listOf(335, 267)))
        assertEquals("300.5", Zapret2GoogleReport.medianMillis(listOf(323, 278)))
        assertEquals("458.5", Zapret2GoogleReport.medianMillis(listOf(489, 428)))
        assertEquals("270", Zapret2GoogleReport.medianMillis(listOf(275, 265)))
        assertEquals("300", Zapret2GoogleReport.medianMillis(listOf(100, 1000, 300)))
        assertEquals("400", Zapret2GoogleReport.medianMillis(listOf(100, 300, 500, 700)))
    }

    @Test fun reportIsGroupedByTargetAndKeepsAllFailures() {
        val attempts = listOf(
            Zapret2GoogleAttempt("plain", 1, Zapret2GoogleProbe.fromWire(
                "v1\tok\t200\t8000\t100\t0\t0".encodeToByteArray()), "google_final"),
            Zapret2GoogleAttempt("fake-5", 1, Zapret2GoogleProbe.fromWire(
                "v1\ttls_failed\t0\t0\t8000\t1\t0".encodeToByteArray()), "youtube_home"),
            Zapret2GoogleAttempt("auto", 1, Zapret2GoogleProbe.fromWire(
                "v1\tcontent_invalid\t200\t220\t120\t0\t0".encodeToByteArray()), "youtube_thumbnail"),
        )
        val report = Zapret2GoogleReport.render("2026-11-22T21:00:00+03:00", "MOBILE", false, attempts)
        assertTrue(report.contains("google_final=www.google.com/"))
        assertTrue(report.contains("youtube_home=www.youtube.com/"))
        assertTrue(report.contains("youtube_thumbnail=i.ytimg.com/"))
        assertTrue(report.contains("plain: 1/1 content"))
        assertTrue(report.contains("fake-5: 0/1 content"))
        assertTrue(report.contains("target=youtube_home strategy=fake-5"))
        assertTrue(report.contains("target=youtube_thumbnail strategy=auto"))
        assertTrue(report.contains("outcome=content_invalid"))
        assertTrue(report.contains("does NOT prove"))
        assertTrue(report.contains("Scope: TCP/HTTPS"))
    }
}
