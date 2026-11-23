package com.dpsmpx.dppass.engine.xray

import com.dpsmpx.dppass.engine.Zapret2ProbeCatalog
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2ServiceReportTest {
    private fun sample(target: String, method: String, attempt: Int,
        outcome: String, http: Int, bytes: Long, duration: Long = 700L) =
        Zapret2GoogleAttempt(method, attempt,
            Zapret2GoogleProbe(outcome, http, bytes, duration, 0, 0), target)

    @Test fun genuineHTMLAndJPEGNeedContentWhileAPIIsTransportOnly() {
        val home = "service_youtube_home"
        val api = "service_youtube_api"
        val thumb = "service_youtube_thumbnail"
        assertTrue(Zapret2ServiceReport.isSuccess(home,
            Zapret2GoogleProbe("ok", 200, 256, 800, 0, 0)))
        assertFalse(Zapret2ServiceReport.isSuccess(home,
            Zapret2GoogleProbe("http_reachable", 404, 256, 800, 0, 0)))
        assertTrue(Zapret2ServiceReport.isSuccess(api,
            Zapret2GoogleProbe("http_reachable", 403, 0, 800, 0, 0)))
        assertFalse(Zapret2ServiceReport.isSuccess(api,
            Zapret2GoogleProbe("quic_verified", 0, 0, 800, 0, 0)))
        assertFalse(Zapret2ServiceReport.isSuccess(api,
            Zapret2GoogleProbe("http_status", 500, 0, 800, 0, 0)))
        assertTrue(Zapret2ServiceReport.isSuccess(thumb,
            Zapret2GoogleProbe("ok", 200, 256, 800, 0, 0)))
        assertFalse(Zapret2ServiceReport.isSuccess(thumb,
            Zapret2GoogleProbe("content_invalid", 200, 256, 800, 0, 0)))
    }

    @Test fun independentComponentsCanHaveDifferentWinningMethods() {
        val rows = buildList {
            for (attempt in 1..3) {
                add(sample("service_youtube_home", "plain", attempt, "timeout_tls", 0, 0))
                add(sample("service_youtube_home", "tlsrec-split", attempt, "ok", 200, 256, 1100))
                add(sample("service_youtube_home", "fake-5", attempt, "ok", 200, 256, 1300))
                add(sample("service_youtube_api", "plain", attempt, "timeout_tls", 0, 0))
                add(sample("service_youtube_api", "tlsrec-split", attempt, "timeout_headers", 0, 0))
                add(sample("service_youtube_api", "fake-5", attempt, "http_reachable", 403, 0, 600))
                add(sample("service_youtube_thumbnail", "plain", attempt, "ok", 200, 256, 300))
                add(sample("service_youtube_thumbnail", "tlsrec-split", attempt, "ok", 200, 256, 600))
                add(sample("service_youtube_thumbnail", "fake-5", attempt, "ok", 200, 256, 900))
            }
        }
        val rank = Zapret2ServiceReport.summarize(rows)
        assertTrue(rank.first { it.target == "service_youtube_home" &&
            it.method == "tlsrec-split" }.stable)
        assertTrue(rank.first { it.target == "service_youtube_api" &&
            it.method == "fake-5" }.stable)
        assertTrue(rank.first { it.target == "service_youtube_thumbnail" &&
            it.method == "plain" }.stable)
        val text = Zapret2ServiceReport.render("MOBILE", rows)
        assertTrue(text.contains("service_youtube").not())
        assertTrue(text.contains("www.youtube.com/"))
        assertTrue(text.contains("youtubei.googleapis.com/"))
        assertTrue(text.contains("i.ytimg.com/"))
        assertTrue(text.contains("API: HTTP 2xx/4xx подтверждает"))
        assertTrue(text.contains("AUTO: not_applied"))
        assertFalse(text.contains("8.8.8.8"))
        assertFalse(text.contains("feed_success"))
    }

    @Test fun duplicateOrMissingAttemptCannotCreateThreeOfThree() {
        val target = Zapret2ProbeCatalog.serviceTargets.first()
        val method = "tlsrec-split"
        val rows = listOf(
            sample(target, method, 1, "ok", 200, 256),
            sample(target, method, 2, "ok", 200, 256),
            sample(target, method, 2, "ok", 200, 256),
        )
        val item = Zapret2ServiceReport.summarize(rows).first { it.target == target &&
            it.method == method }
        assertFalse(item.stable)
        assertEquals(2, item.attempted)
        assertEquals(2, item.successful)
    }
}
