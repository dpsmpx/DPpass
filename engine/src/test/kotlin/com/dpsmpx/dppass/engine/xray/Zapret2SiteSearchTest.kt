package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2SiteSearchTest {
    @Test fun publicDomainValidatorMatchesNativeSecurityContract() {
        assertEquals("www.example.org", Zapret2SiteSearch.normalizedHost("WWW.EXAMPLE.ORG."))
        assertEquals("xn--e1afmkfd.xn--p1ai", Zapret2SiteSearch.normalizedHost("пример.рф"))
        for (bad in listOf("localhost", "router.local", "foo.internal",
                "example.onion", "example.test", "127.0.0.1", "192.168.1.1",
                "https://www.example.org", "user:secret@host.example.org",
                "host.example.org:443", "host.example.org/some/path",
                "example.com?token=secret", "www..example.org", "a", ".org")) {
            assertEquals(null, Zapret2SiteSearch.normalizedHost(bad), "Unsafe $bad")
        }
        assertEquals("site_ip01_a3_:www.example.org",
            Zapret2SiteSearch.trial("www.example.org", 1, 3, false))
        assertEquals("site_quic_ip00_a2_:www.example.org",
            Zapret2SiteSearch.trial("www.example.org", 0, 2, true))
    }

    private fun sample(host: String,ip: Int, attempt: Int, method: String,
        good: Boolean, quic: Boolean = false, millis: Long = 400) =
        Zapret2GoogleAttempt(method, attempt,
            Zapret2GoogleProbe(
                outcome = if (good) (if (quic) "quic_verified" else "ok")
                    else (if (quic) "quic_timeout_no_reply" else "timeout_tls"),
                httpStatus = if (good && !quic) 200 else 0,
                bodyBytes = if (good && !quic) 256 else 0,
                elapsedMillis = if (good) millis else 5_001,
                appliedDelta = 0, skippedDelta = 0,
                dnsFingerprint = "abcdef12", dnsAnswers = 2, ipIndex = ip,
                protocol = if (quic) "quic" else "h1",
                tlsStage = if (good) (if (quic) "quic_tls_verified" else "tls_verified")
                    else (if (quic) "quic_initial_sent" else "clienthello_sent"),
                alpn = if (good) (if (quic) "h3" else "http/1.1") else "-"
            ),
            Zapret2SiteSearch.trial(host, ip, attempt, quic))

    @Test fun completePerIpBaselineVsAllMethodsSelectsStableLowestLatencySet() {
        val host = "video.example.org"
        val rows = buildList {
            for (ip in 0..1) for (attempt in 1..3) {
                add(sample(host, ip, attempt, "plain", false))
                add(sample(host, ip, attempt, "split-1", true, millis = 920))
                add(sample(host, ip, attempt, "tlsrec-split", true, millis = 220))
                add(sample(host, ip, attempt, "fake-5", attempt != 2))
            }
        }
        val rec = Zapret2SiteSearch.recommend(host, 2, rows, quic = false)
        assertEquals("tlsrec-split", rec.method)
        assertTrue(rec.readyToApply)
        assertTrue(rec.candidates.first { it.method == "tlsrec-split" }.stable)
        assertEquals(6, rec.candidates.first { it.method == "tlsrec-split" }.verified)
        assertFalse(rec.candidates.first { it.method == "fake-5" }.stable)
        assertTrue(rec.label.contains("3/3"))
    }

    @Test fun baselineAlwaysWinsWhenAlreadyStable() {
        val host = "web.example.org"
        val rows = buildList {
            for (ip in 0..1) for (attempt in 1..3) {
                add(sample(host, ip, attempt, "plain", true, millis = 1000))
                add(sample(host, ip, attempt, "split-1", true, millis = 20))
            }
        }
        val rec = Zapret2SiteSearch.recommend(host, 2, rows, false)
        assertEquals("plain", rec.method)
        assertTrue(rec.baselineStable)
        assertFalse(rec.readyToApply)
    }

    @Test fun intermittentSiteOrIncompleteSamplesNeverTrain() {
        val host = "api.example.org"
        val rows = buildList {
            for (ip in 0..1) for (attempt in 1..3) {
                add(sample(host, ip, attempt, "plain", false))
                add(sample(host, ip, attempt, "fake-3", ip == 0 || attempt != 3))
            }
        }
        val rec = Zapret2SiteSearch.recommend(host, 2, rows, false)
        assertEquals(null, rec.method)
        assertFalse(rec.readyToApply)
        val duplicated = rows + sample(host, 0, 2, "fake-3", true)
        assertFalse(Zapret2SiteSearch.recommend(host, 2, duplicated, false).readyToApply)
        assertFalse(Zapret2SiteSearch.recommend(host, 2, rows.dropLast(1), false).readyToApply)
    }

    @Test fun baselineTwoOfThreeInsufficientForClaimThatDpiMethodIsBetter() {
        val host = "api.example.org"
        val rows = buildList {
            for (ip in 0..1) for (attempt in 1..3) {
                add(sample(host, ip, attempt, "plain", ip == 0 && attempt < 3))
                add(sample(host, ip, attempt, "split", true))
            }
        }
        val rec = Zapret2SiteSearch.recommend(host, 2, rows, false)
        assertEquals(null, rec.method)
        assertFalse(rec.readyToApply)
    }

    @Test fun quicThreeOfThreeRemainsDiagnosticOnly() {
        val host = "api.example.org"
        val rows = buildList {
            for (ip in 0..1) for (attempt in 1..3) {
                add(sample(host, ip, attempt, "plain", false, quic = true))
                add(sample(host, ip, attempt, "fake-5", true, quic = true))
            }
        }
        val rec = Zapret2SiteSearch.recommend(host, 2, rows, true)
        assertEquals("fake-5", rec.method)
        assertFalse(rec.readyToApply)
        assertTrue(rec.label.contains("только транспорт"))
    }

    @Test fun decodedNativeSiteResponsesAreStrictAndRedacted() {
        val prep = Zapret2GoogleProbe.fromWire(
            "v3\tdns_ready\t200\t0\t120\t0\t0\tabcdef12\t2\t0\tdns\tnone\t-".encodeToByteArray())
        assertEquals("dns_ready", prep.outcome)
        val committed = Zapret2GoogleProbe.fromWire(
            "v3\tauto_applied\t0\t0\t1\t0\t0\tabcdef12\t2\t0\tdns\tnone\t-".encodeToByteArray())
        assertEquals("auto_applied", committed.outcome)
        val host = "api.example.org"
        val rows = (1..3).map { sample(host, 0, it, "plain", false) }
        val rec = Zapret2SiteSearch.recommend(host, 1, rows, false)
        val report = Zapret2SiteSearch.report(host, "MOBILE", false, prep, rows, rec, null)
        assertFalse(report.contains("8.8.8.8"))
        assertFalse(report.contains("/youtubei/"))
        assertTrue(report.contains("Протокол: HTTPS"))
        assertTrue(report.contains("AUTO"))
    }
}
