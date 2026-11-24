package com.dpsmpx.dppass.engine.xray

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DptsLearningTest {
    private val source = """
        dpts 1
        name Verified YouTube HTML
        host www.youtube.com
        learn observe
        https protocols=h1 methods=plain,tlsrec-split ips=2 attempts=3 timeout_ms=5000
    """.trimIndent()

    private fun observations(plan: DptsPlan, methodSuccess: Boolean = true,
        plainSuccess: Boolean = false, candidateHTTP: Int = 200):
        List<Zapret2GoogleAttempt> = plan.probes.map { spec ->
        val good = if (spec.method == "plain") plainSuccess else methodSuccess
        val result = Zapret2GoogleProbe(
            outcome = if (good) "ok" else "timeout_tls_no_reply",
            httpStatus = if (good) candidateHTTP else 0,
            bodyBytes = if (good) 256 else 0,
            elapsedMillis = if (good) 260 else 5000,
            appliedDelta = 0, skippedDelta = 0, dnsFingerprint = "sample",
            dnsAnswers = 8, ipIndex = spec.ipIndex, protocol = "h1",
            tlsStage = if (good) "tls_verified" else "clienthello_sent",
            alpn = if (good) "http/1.1" else "-"
        )
        Zapret2GoogleAttempt(spec.method, spec.attempt, result, spec.target)
    }

    @Test fun completeThreeOfThreeOnTwoIPsWithFailedPlainYieldsOnlyProvenMethod() {
        val plan = DptsScript.compile(source)
        assertEquals(listOf("tlsrec-split"),
            DptsLearning.confirmedWinners(plan, observations(plan)))
    }

    @Test fun noTrainingFromAPITimeoutsOrAnIncompleteOrDuplicatedSequence() {
        val plan = DptsScript.compile(source)
        assertTrue(DptsLearning.confirmedWinners(plan,
            observations(plan, methodSuccess = false)).isEmpty())
        assertTrue(DptsLearning.confirmedWinners(plan,
            observations(plan, plainSuccess = true)).isEmpty())
        assertTrue(DptsLearning.confirmedWinners(plan,
            observations(plan, candidateHTTP = 404)).isEmpty())
        assertTrue(DptsLearning.confirmedWinners(plan,
            observations(plan).dropLast(1)).isEmpty())
        val original = observations(plan)
        assertTrue(DptsLearning.confirmedWinners(plan,
            original.dropLast(1) + original.first()).isEmpty())

        val disabled = DptsScript.compile(source.replace("learn observe", "learn off"))
        assertTrue(DptsLearning.confirmedWinners(disabled,
            observations(disabled)).isEmpty())

        val api = DptsScript.compile(source.replace("www.youtube.com",
            "youtubei.googleapis.com"))
        assertTrue(DptsLearning.confirmedWinners(api,
            observations(api)).isEmpty())
    }

    @Test fun explicitLegacySuiteCannotTrainFromScript() {
        val plan = DptsScript.compile(
            "dpts 1\nname API sweep\nhost youtubei.googleapis.com\n" +
                "learn observe\nsuite api_ipv4_sweep")
        assertTrue(DptsLearning.confirmedWinners(plan, emptyList()).isEmpty())
    }
}
