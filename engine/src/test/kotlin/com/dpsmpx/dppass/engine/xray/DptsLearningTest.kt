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
            appliedDelta = 0, skippedDelta = 0, dnsFingerprint = "abcdef12",
            dnsAnswers = 8, ipIndex = spec.ipIndex, protocol = spec.wireProtocol,
            tlsStage = if (good) "tls_verified" else "clienthello_sent",
            alpn = if (!good) "-" else if (spec.protocol == "h2") "h2" else "http/1.1"
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

    @Test fun http2ProofAndPartialAddressEvidenceStaySeparate() {
        val plan = DptsScript.compile(source.replace("protocols=h1", "protocols=h2"))
        val rows = observations(plan)
        assertEquals(listOf("tlsrec-split"), DptsLearning.confirmedWinners(plan, rows))
        val partial = rows.mapIndexed { i, row ->
            if (plan.probes[i].ipIndex == 0 && row.strategy != "plain")
                row.copy(result = row.result.copy(outcome = "timeout_tls_no_reply", tlsStage = "clienthello_sent",
                    httpStatus = 0, bodyBytes = 0, alpn = "-"))
            else row
        }
        val evidence = DptsLearning.analyze(plan, partial)
        assertEquals("verified_single_ip_only", evidence.reason)
        assertEquals(listOf(DptsLearning.AddressProof(1, "h2", "tlsrec-split")), evidence.addressProofs)
        assertTrue(evidence.winners.isEmpty())
    }

    @Test fun mixedTlsVersionAndHttpsRowsUseTheSameWireBinding() {
        val plan = DptsScript.compile(source + "\ntls versions=12,13 methods=plain ips=1 attempts=1")
        val rows = observations(plan)
        val evidence = DptsLearning.analyze(plan, rows)
        assertEquals("verified_two_ips", evidence.reason)
        assertEquals(6, evidence.htmlVerified)
        assertEquals(listOf("tlsrec-split"), evidence.winners)
        val wrongProtocol = rows.mapIndexed { i, row ->
            if (plan.probes[i].phase == "tls") row.copy(result = row.result.copy(protocol = "h2")) else row
        }
        assertEquals("mismatched_probe_rows", DptsLearning.analyze(plan, wrongProtocol).reason)
    }

    @Test fun malformedDnsOrContradictoryBaselineCannotTrain() {
        val plan = DptsScript.compile(source)
        val rows = observations(plan)
        for (change in listOf<(Zapret2GoogleProbe) -> Zapret2GoogleProbe>(
            { it.copy(dnsFingerprint = "invalid") },
            { it.copy(dnsAnswers = 1) },
            { it.copy(dnsAnswers = 9) },
        )) {
            val changed = rows.map { it.copy(result = change(it.result)) }
            val evidence = DptsLearning.analyze(plan, changed)
            assertEquals("dns_address_set_changed", evidence.reason)
            assertEquals(0, evidence.transportVerified)
            assertEquals(0, evidence.htmlVerified)
        }
        val contradictory = rows.map { row ->
            if (row.strategy == "plain") row.copy(result = row.result.copy(tlsStage = "tls_verified")) else row
        }
        assertTrue(DptsLearning.confirmedWinners(plan, contradictory).isEmpty())
        val wrongAlpn = rows.map { row ->
            if (row.strategy != "plain") row.copy(result = row.result.copy(alpn = "h2")) else row
        }
        val evidence = DptsLearning.analyze(plan, wrongAlpn)
        assertEquals(0, evidence.transportVerified)
        assertEquals(0, evidence.htmlVerified)
        assertTrue(evidence.winners.isEmpty())
    }

    @Test fun malformedPlanCannotCountDuplicateNativeIdentities() {
        val original = DptsScript.compile(source)
        val plan = original.copy(probes = original.probes + original.probes.first())
        val evidence = DptsLearning.analyze(plan, observations(plan))
        assertEquals("duplicate_probe_identity", evidence.reason)
        assertEquals(0, evidence.transportVerified)
        assertEquals(0, evidence.htmlVerified)
        assertTrue(evidence.winners.isEmpty())
    }

    @Test fun tlsOnlyAndVerifiedHttpUseDistinctEvidenceCounters() {
        val plan = DptsScript.compile(source)
        val rows = observations(plan).map { row ->
            if (row.strategy == "plain") row else row.copy(result = row.result.copy(
                outcome = "timeout_headers", httpStatus = 0, bodyBytes = 0))
        }
        val evidence = DptsLearning.analyze(plan, rows)
        assertEquals(6, evidence.tlsVerified)
        assertEquals(0, evidence.transportVerified)
        assertEquals(0, evidence.htmlVerified)
        assertEquals("transport_only_not_content", evidence.reason)
        assertTrue(evidence.winners.isEmpty())
        val malformed = DptsLearning.analyze(plan.copy(budgetMs = 1), observations(plan))
        assertEquals("invalid_probe_plan", malformed.reason)
        assertEquals(0, malformed.tlsVerified)
        assertTrue(malformed.winners.isEmpty())
    }

    @Test fun explicitLegacySuiteCannotTrainFromScript() {
        val plan = DptsScript.compile(
            "dpts 1\nname API sweep\nhost youtubei.googleapis.com\n" +
                "learn observe\nsuite api_ipv4_sweep")
        assertTrue(DptsLearning.confirmedWinners(plan, emptyList()).isEmpty())
    }

    @Test fun impossibleBodySizesCannotProvideHtmlProof() {
        val plan = DptsScript.compile(source)
        val rows = observations(plan)
        for (size in listOf(-1L, 127L, 257L, Long.MAX_VALUE)) {
            val changed = rows.map { row ->
                if (row.strategy == "plain") row
                else row.copy(result = row.result.copy(bodyBytes = size))
            }
            val evidence = DptsLearning.analyze(plan, changed)
            assertEquals(0, evidence.htmlVerified)
            assertTrue(evidence.winners.isEmpty())
        }
        for (size in listOf(128L, 256L)) {
            val changed = rows.map { row ->
                if (row.strategy == "plain") row
                else row.copy(result = row.result.copy(bodyBytes = size))
            }
            assertEquals(listOf("tlsrec-split"), DptsLearning.confirmedWinners(plan, changed))
        }
    }
}
