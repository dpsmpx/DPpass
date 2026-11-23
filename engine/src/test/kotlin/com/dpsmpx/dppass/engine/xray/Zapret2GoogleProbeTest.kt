package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import com.dpsmpx.dppass.engine.Zapret2Stages
import java.nio.ByteBuffer
import java.nio.ByteOrder
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2GoogleProbeTest {
    @Test fun completeStrategyAndDestinationCatalogs() {
        assertEquals(8, Zapret2ProbeCatalog.strategies.size)
        assertEquals(listOf("google_final", "google_search", "youtube_home",
            "youtube_api_transport", "youtube_api_ipv4", "youtube_thumbnail"),
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
        val api = Zapret2GoogleProbe.fromWire("v1\thttp_reachable\t403\t126\t180\t1\t0".encodeToByteArray())
        assertTrue(api.httpReachable)
        assertFalse(api.success) // never credit API response as working feed
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

    @Test fun apiHTTPIsReportedOnlyAsTransportNotContent() {
        val attempt = Zapret2GoogleAttempt("plain", 1, Zapret2GoogleProbe.fromWire(
            "v1\\thttp_reachable\\t403\\t126\\t150\\t0\\t0"
                .replace("\\t", "\t").encodeToByteArray()), "youtube_api_transport")
        val report = Zapret2GoogleReport.render("test", "MOBILE", false, listOf(attempt))
        assertTrue(report.contains("plain: 1/1 HTTP transport (not API content)"))
        assertTrue(report.contains("target=youtube_api_transport strategy=plain"))
        assertTrue(report.contains("outcome=http_reachable http=403"))
        assertEquals(null, Zapret2GoogleReport.provisionalYouTubeHint(listOf(attempt)))
    }

    @Test fun clipboardReportIncludesStageIPv4IPv6Breakdown() {
        val counters = LongArray(21)
        counters[0] = 7
        counters[3] = 4
        counters[15] = 3
        counters[16] = 3
        counters[17] = 1
        counters[18] = 1
        counters[19] = 2
        counters[20] = 1
        val wire = ByteBuffer.allocate(1 + 21 * 8).order(ByteOrder.BIG_ENDIAN)
        wire.put(2.toByte())
        counters.forEach { wire.putLong(it) }
        val stages = Zapret2Stages.fromWire(wire.array())!!
        val report = Zapret2GoogleReport.render("test", "MOBILE", false, emptyList(), stages)
        assertTrue(report.contains("tcp_dial_unreachable=4"))
        assertTrue(report.contains("tcp_unreachable_ipv4=1"))
        assertTrue(report.contains("tcp_unreachable_ipv6=2"))
        assertTrue(report.contains("tcp_unreachable_unknown=1"))
        assertTrue(report.contains("include background apps"))
    }

    @Test fun provisionalAPITransportPreferenceRequiresTwoRepliesAndNoBaseline() {
        fun row(strategy: String, attempt: Int, outcome: String, status: Int) =
            Zapret2GoogleAttempt(strategy, attempt,
                Zapret2GoogleProbe.fromWire(
                    "v1\\t$outcome\\t$status\\t120\\t420\\t1\\t0"
                        .replace("\\t", "\t").encodeToByteArray()), "youtube_api_transport")
        val rows = listOf(
            row("plain", 1, "timeout", 0),
            row("plain", 2, "timeout", 0),
            row("fake-5", 1, "http_reachable", 403),
            row("fake-5", 2, "http_reachable", 404),
            row("auto", 1, "http_reachable", 400),
            row("auto", 2, "http_reachable", 404),
        )
        assertEquals("fake-5", Zapret2GoogleReport.provisionalAPITransportHint(rows))
        assertTrue(Zapret2GoogleReport.render("test", "MOBILE", false, rows)
            .contains("Provisional exact-host AUTO transport candidate: fake-5 for youtubei.googleapis.com"))
        assertEquals(null, Zapret2GoogleReport.provisionalYouTubeHint(rows))
        assertEquals(null, Zapret2GoogleReport.provisionalAPITransportHint(
            rows.filterNot { it.strategy == "plain" } +
                row("plain", 1, "http_reachable", 403) +
                row("plain", 2, "http_reachable", 403)))
        assertEquals(null, Zapret2GoogleReport.provisionalAPITransportHint(
            rows.filterNot { it.strategy == "fake-5" }))
        assertEquals(null, Zapret2GoogleReport.provisionalAPITransportHint(
            rows.filterNot { it.strategy == "fake-5" } +
                row("fake-5", 1, "http_reachable", 403) +
                row("fake-5", 2, "redirect", 301)))
    }

    @Test fun provisionalAutoCandidateRequiresTwoVerifiedYouTubeHTMLResponses() {
        fun row(target: String, strategy: String, attempt: Int, outcome: String, ms: Long) =
            Zapret2GoogleAttempt(strategy, attempt,
                Zapret2GoogleProbe.fromWire(
                    "v1\\t$outcome\\t${if (outcome == "ok") 200 else 0}\\t${if (outcome == "ok") 8192 else 0}\\t$ms\\t1\\t0"
                        .replace("\\t", "\t").encodeToByteArray()), target)
        val youtube = listOf(
            row("youtube_home", "plain", 1, "timeout", 8000),
            row("youtube_home", "plain", 2, "timeout", 8000),
            row("youtube_home", "tlsrec-split", 1, "ok", 934),
            row("youtube_home", "tlsrec-split", 2, "ok", 1118),
            row("youtube_home", "fake-5", 1, "ok", 1202),
            row("youtube_home", "fake-5", 2, "ok", 1474),
            row("youtube_home", "auto", 1, "timeout", 8000),
            row("youtube_home", "auto", 2, "timeout", 8000),
        )
        assertEquals("tlsrec-split", Zapret2GoogleReport.provisionalYouTubeHint(youtube))
        assertTrue(Zapret2GoogleReport.render("test", "MOBILE", false, youtube)
            .contains("Provisional exact-host AUTO candidate: tlsrec-split"))
        assertEquals(null, Zapret2GoogleReport.provisionalYouTubeHint(
            youtube.filterNot { it.strategy == "plain" } +
                row("youtube_home", "plain", 1, "ok", 500) +
                row("youtube_home", "plain", 2, "ok", 500)))
        assertEquals(null, Zapret2GoogleReport.provisionalYouTubeHint(
            youtube.filterNot { it.strategy == "tlsrec-split" || it.strategy == "fake-5" }))
        assertEquals(null, Zapret2GoogleReport.provisionalYouTubeHint(
            youtube.map { if (it.strategy == "tlsrec-split") it.copy(target = "google_final") else it }
                .filterNot { it.strategy == "fake-5" }))
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
        assertTrue(report.contains("youtube_api_transport=youtubei.googleapis.com/"))
        assertTrue(report.contains("youtube_thumbnail=i.ytimg.com/"))
        assertTrue(report.contains("plain: 1/1 content"))
        assertTrue(report.contains("fake-5: 0/1 content"))
        assertTrue(report.contains("target=youtube_home strategy=fake-5"))
        assertTrue(report.contains("target=youtube_thumbnail strategy=auto"))
        assertTrue(report.contains("outcome=content_invalid"))
        assertTrue(report.contains("does NOT prove"))
        assertTrue(report.contains("Scope: TCP/HTTPS"))
    }

    @Test fun stageTimeoutsAreValidAndNotMisclassifiedAsContent() {
        for (stage in listOf("timeout_dial", "timeout_tls", "timeout_write",
                "timeout_headers", "timeout_body")) {
            val r = Zapret2GoogleProbe.fromWire(
                "v1\t$stage\t0\t0\t8000\t0\t0".replace("\\t", "\t").encodeToByteArray())
            assertEquals(stage, r.outcome)
            assertFalse(r.success)
            assertFalse(r.httpReachable)
        }
    }

    @Test fun ipv4ControlIsAComparisonNotAutomaticNormalVpnStrategy() {
        fun attempt(target: String, outcome: String, status: Int) =
            Zapret2GoogleAttempt("tlsrec-split", 1,
                Zapret2GoogleProbe.fromWire(
                    "v1\t$outcome\t$status\t128\t1700\t1\t0"
                        .replace("\\t", "\t").encodeToByteArray()), target)
        val report = Zapret2GoogleReport.render(
            "test", "MOBILE", false, listOf(
                attempt("youtube_api_transport", "timeout_tls", 0),
                attempt("youtube_api_ipv4", "http_reachable", 403),
                attempt("google_search", "ok", 200),
            ))
        assertTrue(report.contains("YouTube API control: configured_DNS_HTTP=0; IPv4_only_HTTP=1"))
        assertTrue(report.contains("timeout_tls"))
        assertTrue(report.contains("HTML (not verified search results)"))
        assertTrue(report.contains("NOT ordinary VPN routing"))
        assertEquals(null, Zapret2GoogleReport.provisionalAPITransportHint(listOf(
            attempt("youtube_api_ipv4", "http_reachable", 403))))
    }


    @Test fun verifiedDoHFingerprintV2AndLegacyV1RemainCompatible() {
        val passed = Zapret2GoogleProbe.fromWire(
            "v2\\ttimeout_tls\\t0\\t0\\t12000\\t0\\t0\\tab12ef34\\t4"
                .replace("\\t", "\t").encodeToByteArray())
        assertEquals("timeout_tls", passed.outcome)
        assertEquals(4, passed.dnsAnswers)
        assertEquals("ab12ef34", passed.dnsFingerprint)
        assertFalse(passed.httpReachable)
        val blocked = Zapret2GoogleProbe.fromWire(
            "v2\\tdoh_timeout_tls\\t0\\t0\\t12000\\t0\\t0\\t-\\t0"
                .replace("\\t", "\t").encodeToByteArray())
        assertEquals("doh_timeout_tls", blocked.outcome)
        assertEquals(0, blocked.dnsAnswers)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire(
            "v2\\ttimeout_tls\\t0\\t0\\t0\\t0\\t0\\t1.2.3.4\\t1"
                .replace("\\t", "\t").encodeToByteArray()).outcome)
        val legacy = Zapret2GoogleProbe.fromWire("v1\\tok\\t200\\t8192\\t250\\t1\\t0"
            .replace("\\t", "\t").encodeToByteArray())
        assertTrue(legacy.success)
        assertEquals("", legacy.dnsFingerprint)
    }

    @Test fun dnsReportSeparatesResolverFailureFromTargetTLSFailure() {
        fun row(target: String, outcome: String, digest: String, count: Int) =
            Zapret2GoogleAttempt("fake-5", 1,
                Zapret2GoogleProbe.fromWire(
                    "v2\\t$outcome\\t0\\t0\\t8000\\t0\\t0\\t$digest\\t$count"
                        .replace("\\t", "\t").encodeToByteArray()), target)
        val report = Zapret2DNSComparisonReport.render("2026-11-23", "MOBILE",
            listOf(row("youtube_api_dns_cloudflare", "timeout_tls", "abcdef01", 2),
                row("youtube_api_dns_google", "doh_timeout_tls", "-", 0),
                row("youtube_api_dns_quad9", "timeout_tls", "0123abcd", 1)))
        assertTrue(report.contains("doh_timeout_tls"))
        assertTrue(report.contains("Multiple DoH A-answer sets observed"))
        assertTrue(report.contains("ordinary VPN DNS and routing are unchanged"))
        assertFalse(report.contains("1.2.3.4"))
        assertEquals(4, Zapret2ProbeCatalog.dnsTargets.size)
        assertEquals(listOf("fake-5","tlsrec-split"), Zapret2ProbeCatalog.dnsStrategies)
    }


    @Test fun matrixV3StrictProtocolStagesAndBackwardsCompatibility() {
        val tls = Zapret2GoogleProbe.fromWire(
            "v3\\ttimeout_tls_no_reply\\t0\\t0\\t5000\\t1\\t0\\t6f706c12\\t8\\t7\\th2\\tclienthello_sent\\t-"
                .replace("\\t", "\t").encodeToByteArray())
        assertEquals("timeout_tls_no_reply", tls.outcome)
        assertEquals("clienthello_sent", tls.tlsStage)
        assertEquals("h2", tls.protocol)
        assertEquals(7, tls.ipIndex)
        assertEquals(8, tls.dnsAnswers)
        val serverHello = Zapret2GoogleProbe.fromWire(
            "v3\\ttimeout_tls_after_reply\\t0\\t0\\t5000\\t0\\t0\\t6f706c12\\t8\\t5\\th1\\tserverhello_seen\\t-"
                .replace("\\t", "\t").encodeToByteArray())
        assertEquals("timeout_tls_after_reply", serverHello.outcome)
        assertEquals("serverhello_seen", serverHello.tlsStage)
        val dns = Zapret2GoogleProbe.fromWire(
            "v3\\tdoh_http_status\\t400\\t0\\t311\\t0\\t0\\t-\\t0\\t0\\tdns\\tnone\\t-"
                .replace("\\t", "\t").encodeToByteArray())
        assertEquals("doh_http_status", dns.outcome)
        assertEquals(400, dns.httpStatus)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire(
            "v3\\thttp_reachable\\t403\\t100\\t200\\t0\\t0\\t6f706c12\\t8\\t8\\th2\\ttls_verified\\th2"
                .replace("\\t", "\t").encodeToByteArray()).outcome)
        assertEquals("contract_error", Zapret2GoogleProbe.fromWire(
            "v3\\thttp_reachable\\t403\\t100\\t200\\t0\\t0\\t6f706c12\\t8\\t0\\th3\\ttls_verified\\th3"
                .replace("\\t", "\t").encodeToByteArray()).outcome)
        assertTrue(Zapret2GoogleProbe.fromWire(
            "v1\\tok\\t200\\t8192\\t240\\t0\\t0".replace("\\t", "\t").encodeToByteArray()).success)
    }

    @Test fun matrixReportKeepsPerIPStagesAndDoHHTTPStatusWithoutRawAddresses() {
        fun row(target: String, strategy: String, wire: String) =
            Zapret2GoogleAttempt(strategy, 1,
                Zapret2GoogleProbe.fromWire(wire.replace("\\t", "\t").encodeToByteArray()), target)
        val rows = listOf(
            row("youtube_api_matrix_cloudflare_prepare", "plain",
                "v3\\tdns_ready\\t200\\t0\\t100\\t0\\t0\\t6f706c12\\t8\\t0\\tdns\\tnone\\t-"),
            row("youtube_api_matrix_google_prepare", "plain",
                "v3\\tdns_ready\\t200\\t0\\t120\\t0\\t0\\t6f706c12\\t8\\t0\\tdns\\tnone\\t-"),
            row("youtube_api_matrix_quad9_prepare", "plain",
                "v3\\tdoh_http_status\\t400\\t0\\t300\\t0\\t0\\t-\\t0\\t0\\tdns\\tnone\\t-"),
            row("youtube_api_matrix_cloudflare_ip07_h2", "fake-5",
                "v3\\ttimeout_tls_no_reply\\t0\\t0\\t5000\\t0\\t0\\t6f706c12\\t8\\t7\\th2\\tclienthello_sent\\t-"),
            row("youtube_api_matrix_cloudflare_ip07_quic", "plain",
                "v3\\tquic_verified\\t0\\t0\\t220\\t0\\t0\\t6f706c12\\t8\\t7\\tquic\\tquic_tls_verified\\th3"),
        )
        val report = Zapret2MatrixReport.render("2026-11-23", "MOBILE", rows)
        assertTrue(report.contains("resolver=quad9 outcome=doh_http_status doh_http=400"))
        assertTrue(report.contains("Duplicate short RRset fingerprint"))
        assertTrue(report.contains("ipv4_index=7"))
        assertTrue(report.contains("stage=clienthello_sent"))
        assertTrue(report.contains("quic_verified=1"))
        assertTrue(report.contains("No global DNS, routing or AUTO preference is changed"))
        assertFalse(report.contains("8.8.8.8"))
        assertEquals(3, Zapret2ProbeCatalog.matrixStrategies.size)
        assertEquals(3, Zapret2ProbeCatalog.matrixProviders.size)
    }
}
