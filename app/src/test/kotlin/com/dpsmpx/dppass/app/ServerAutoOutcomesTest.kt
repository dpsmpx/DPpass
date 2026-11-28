package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.config.ProtocolSpec
import com.dpsmpx.dppass.config.SecuritySpec
import com.dpsmpx.dppass.config.ServerProfile
import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.TransportSpec
import com.dpsmpx.dppass.connection.AttemptRecord
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.PlannedAttempt
import com.dpsmpx.dppass.connection.ServerLearningEvidence
import com.dpsmpx.dppass.core.Endpoint
import com.dpsmpx.dppass.core.Host
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import com.dpsmpx.dppass.diagnostics.Diagnostic
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.diagnostics.MemoryLogSink
import com.dpsmpx.dppass.diagnostics.Secret
import com.dpsmpx.dppass.network.NetworkType
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse

class ServerAutoOutcomesTest {
    private val tcpA = profile("tcp-a")
    private val tcpB = profile("tcp-b")
    private val quicA = profile("quic-a", quic = true)
    private val quicB = profile("quic-b", quic = true)
    private val failed = Diagnostic.error(DiagCode.ENDPOINT_UNREACHABLE, "test failure")

    @Test fun separatesPlannedMovesFromActualAttemptsAndKeepsContextsIndependent() {
        val original = plan(tcpA, tcpB, quicA, quicB)
        val executed = plan(tcpB, tcpA, quicB, quicA)
        val attempts = listOf(
            record(tcpB, false, failed, ServerLearningEvidence.MEASURED_FAILURE),
            record(tcpA, false, failed, ServerLearningEvidence.NONE),
            record(quicB, true, null, ServerLearningEvidence.VERIFIED_SUCCESS),
        )
        val (tcp, quic) = serverAutoOutcomes(original, executed, attempts, NetworkType.WIFI)
        assertEquals(ServerAutoContextOutcome(ServerAutoContext.WIFI_TCP, 2, 2, 2, 2,
            0, 1, ServerLearningEvidence.MEASURED_FAILURE, true), tcp)
        assertEquals(1, tcp.unmeasured)
        assertEquals(ServerAutoContextOutcome(ServerAutoContext.WIFI_QUIC, 2, 2, 1, 1,
            1, 0, null, false), quic)
    }

    @Test fun firstRecordAndFirstAdmittedEvidenceHaveSeparateMeanings() {
        val original = plan(tcpA, tcpB, quicA)
        val attempts = listOf(
            record(tcpA, false, failed, ServerLearningEvidence.VERIFIED_SUCCESS),
            record(tcpA, false, failed, ServerLearningEvidence.MEASURED_FAILURE),
            record(tcpA, false, failed, ServerLearningEvidence.MEASURED_FAILURE),
            record(tcpB, true, null, ServerLearningEvidence.NONE),
            record(quicB, true, null, ServerLearningEvidence.VERIFIED_SUCCESS),
        )
        val (tcp, quic) = serverAutoOutcomes(original, original, attempts, NetworkType.MOBILE)
        assertEquals(ServerAutoContextOutcome(ServerAutoContext.MOBILE_TCP, 2, 0, 2, 0,
            0, 1, ServerLearningEvidence.NONE, false), tcp)
        assertEquals(1, tcp.unmeasured)
        assertEquals(ServerAutoContextOutcome(ServerAutoContext.MOBILE_QUIC, 1, 0, 0, 0,
            0, 0, null, false), quic)
    }

    @Test fun logsOnlyCountsAndCategoriesForPlannerAndScoredRuns() {
        val original = plan(tcpA)
        val attempted = record(tcpA, true, null, ServerLearningEvidence.VERIFIED_SUCCESS)
        val outcome = serverAutoOutcomes(original, original, listOf(attempted), NetworkType.ETHERNET).single()
        val sink = MemoryLogSink()
        val log = Logger("test", sink, { 0 })
        outcome.log(log, null)
        outcome.log(log, 8)
        val (planner, scored) = sink.snapshot()
        assertEquals("server_auto_outcome", planner.event)
        assertEquals(mapOf(
            "context" to "OTHER_TCP", "model_scored" to "false", "observations_before" to "null",
            "candidates" to "1", "planned_moved" to "0", "attempted" to "1", "attempted_moved" to "0",
            "verified_successes" to "1", "measured_failures" to "0", "unmeasured" to "0",
            "first_attempt" to "VERIFIED_SUCCESS", "first_moved" to "false",
        ), planner.fields)
        assertEquals(planner.fields + mapOf("model_scored" to "true", "observations_before" to "8"), scored.fields)
        assertFalse(planner.render().contains(tcpA.id.value))
        assertFalse(scored.render().contains("example.net"))
    }

    @Test fun contextOrdinalsMatchTheExistingV4Layout() {
        assertEquals(ServerContextHead.CONTEXTS, ServerAutoContext.entries.size)
        for ((network, offset) in listOf(NetworkType.MOBILE to 0, NetworkType.WIFI to 2, NetworkType.OTHER to 4)) {
            assertEquals(offset, ServerAutoContext.of(network, TransportClass.TCP_STREAM).ordinal)
            assertEquals(offset, ServerAutoContext.of(network, TransportClass.HTTP_CDN).ordinal)
            assertEquals(offset + 1, ServerAutoContext.of(network, TransportClass.UDP_QUIC).ordinal)
        }
    }

    private fun profile(id: String, quic: Boolean = false) = ServerProfile(
        ProfileId(id), id, Endpoint(Host.Domain("$id.example.net"), 443),
        if (quic) ProtocolSpec.Hysteria2(Secret("synthetic")) else ProtocolSpec.Trojan(Secret("synthetic")),
        if (quic) TransportSpec.Native else TransportSpec.Tcp, SecuritySpec.None,
    )

    private fun plan(vararg profiles: ServerProfile) =
        ConnectionPlan(profiles.map { PlannedAttempt(it, emptyList()) }, emptyList(), null, null)

    private fun record(profile: ServerProfile, ok: Boolean, failure: Diagnostic?, evidence: ServerLearningEvidence) =
        AttemptRecord(profile.id, emptyList(), ok, failure, evidence)
}
