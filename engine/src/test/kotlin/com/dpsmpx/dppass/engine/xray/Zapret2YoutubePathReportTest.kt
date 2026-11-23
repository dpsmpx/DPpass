package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class Zapret2YoutubePathReportTest {
    private fun row(service: String, protocol: String, method: String,
        outcome: String, code: Int, bytes: Long, alpn: String,
        attempt: Int = 1): Zapret2GoogleAttempt =
        Zapret2GoogleAttempt(method, attempt,
            Zapret2GoogleProbe(outcome, code, bytes, 1050, 0, 0,
                "8020f565", 8, 0, protocol, "tls_verified", alpn),
            Zapret2YoutubePathReport.trial(service,protocol))

    @Test fun everyServiceProtocolAndStrategyIsAllowlisted() {
        assertEquals(listOf("home","api","thumb"),Zapret2YoutubePathReport.services)
        assertEquals(listOf("h1","h2"),Zapret2YoutubePathReport.protocols)
        assertEquals(listOf("plain","tlsrec-split","fake-5"),
            Zapret2YoutubePathReport.methods)
        assertEquals("yt_path_prepare_api",Zapret2YoutubePathReport.preparation("api"))
        assertEquals("yt_path_home_h2",Zapret2YoutubePathReport.trial("home","h2"))
    }

    @Test fun http2RequiresVerifiedAlpnAndExpectedContent() {
        val good = row("home","h2","tlsrec-split","ok",200,256,"h2")
        assertTrue(Zapret2YoutubePathReport.verified(good))
        assertFalse(Zapret2YoutubePathReport.verified(good.copy(
            result=good.result.copy(alpn="http/1.1"))))
        assertFalse(Zapret2YoutubePathReport.verified(good.copy(
            result=good.result.copy(tlsStage="clienthello_sent"))))
        assertFalse(Zapret2YoutubePathReport.verified(good.copy(
            result=good.result.copy(bodyBytes=0))))
        assertTrue(Zapret2YoutubePathReport.verified(
            row("thumb","h1","fake-5","ok",200,256,"http/1.1")))
    }

    @Test fun anonymousApi403IsTransportOnlyAndNoVideoClaim() {
        val api = row("api","h2","fake-5","http_reachable",403,0,"h2")
        assertTrue(Zapret2YoutubePathReport.verified(api))
        assertFalse(Zapret2YoutubePathReport.verified(
            row("api","h2","fake-5","timeout_headers",0,0,"h2")))
        val prep=Zapret2GoogleAttempt("plain",1,
            Zapret2GoogleProbe("dns_ready",200,0,100,0,0,
                "8020f565",8,0,"dns","none","-"),
            Zapret2YoutubePathReport.preparation("api"))
        val report=Zapret2YoutubePathReport.render("MOBILE",listOf(prep),listOf(api))
        assertTrue(report.contains("api dns=dns_ready"))
        assertTrue(report.contains("h2 fake-5: 1/1"))
        assertTrue(report.contains("НЕ проверялись"))
        assertTrue(report.contains("API 2xx/4xx"))
        assertFalse(report.contains("8.8.8.8"))
    }
}
