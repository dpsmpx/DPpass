package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.config.TransportClass
import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.connection.AttemptRecord
import com.dpsmpx.dppass.connection.ConnectionPlan
import com.dpsmpx.dppass.connection.ServerLearningEvidence
import com.dpsmpx.dppass.diagnostics.Logger
import com.dpsmpx.dppass.network.NetworkType

/** Порядок контекстов соответствует строкам серверной модели V4. */
internal enum class ServerAutoContext {
    MOBILE_TCP, MOBILE_QUIC, WIFI_TCP, WIFI_QUIC, OTHER_TCP, OTHER_QUIC;

    companion object {
        fun of(network: NetworkType, transport: TransportClass): ServerAutoContext {
            val offset = when (network) {
                NetworkType.MOBILE -> 0
                NetworkType.WIFI -> 2
                else -> 4
            }
            return entries[offset + if (transport == TransportClass.UDP_QUIC) 1 else 0]
        }
    }
}

internal fun AttemptRecord.measuredServerEvidence(): ServerLearningEvidence = when (serverLearningEvidence) {
    ServerLearningEvidence.VERIFIED_SUCCESS ->
        if (ok && failure == null) ServerLearningEvidence.VERIFIED_SUCCESS else ServerLearningEvidence.NONE
    ServerLearningEvidence.MEASURED_FAILURE ->
        if (!ok && failure != null) ServerLearningEvidence.MEASURED_FAILURE else ServerLearningEvidence.NONE
    ServerLearningEvidence.NONE -> ServerLearningEvidence.NONE
}

internal data class ServerAutoContextOutcome(
    val context: ServerAutoContext,
    val candidates: Int,
    val plannedMoved: Int,
    val attempted: Int,
    val attemptedMoved: Int,
    val verifiedSuccesses: Int,
    val measuredFailures: Int,
    val firstEvidence: ServerLearningEvidence?,
    val firstMoved: Boolean,
) {
    val unmeasured: Int get() = attempted - verifiedSuccesses - measuredFailures

    fun log(logger: Logger, observationsBefore: Long?) {
        logger.info("server_auto_outcome",
            "context" to context,
            "model_scored" to (observationsBefore != null),
            "observations_before" to observationsBefore,
            "candidates" to candidates,
            "planned_moved" to plannedMoved,
            "attempted" to attempted,
            "attempted_moved" to attemptedMoved,
            "verified_successes" to verifiedSuccesses,
            "measured_failures" to measuredFailures,
            "unmeasured" to unmeasured,
            "first_attempt" to firstEvidence,
            "first_moved" to firstMoved)
    }
}

/** В сводку попадают только числовые итоги и фиксированные категории. */
internal fun serverAutoOutcomes(
    original: ConnectionPlan, executed: ConnectionPlan, attempts: List<AttemptRecord>, network: NetworkType,
): List<ServerAutoContextOutcome> {
    val originalPositions = original.attempts.mapIndexed { index, attempt -> attempt.profile.id to index }.toMap()
    val attemptsByProfile = attempts.groupBy { it.profileId }
    val first = attempts.firstOrNull()
    return executed.attempts.withIndex()
        .groupBy { ServerAutoContext.of(network, it.value.profile.transportClass) }
        .map { (context, candidates) ->
            var plannedMoved = 0
            var attempted = 0
            var attemptedMoved = 0
            var verifiedSuccesses = 0
            var measuredFailures = 0
            var firstEvidence: ServerLearningEvidence? = null
            var firstMoved = false
            for ((position, candidate) in candidates) {
                val id = candidate.profile.id
                val moved = originalPositions.getValue(id) != position
                if (moved) plannedMoved++
                val records = attemptsByProfile[id] ?: continue
                attempted++
                if (moved) attemptedMoved++
                when (records.firstNotNullOfOrNull { record ->
                    record.measuredServerEvidence().takeUnless { it == ServerLearningEvidence.NONE }
                }) {
                    ServerLearningEvidence.VERIFIED_SUCCESS -> verifiedSuccesses++
                    ServerLearningEvidence.MEASURED_FAILURE -> measuredFailures++
                    else -> Unit
                }
                if (first != null && first.profileId == id) {
                    firstEvidence = first.measuredServerEvidence()
                    firstMoved = moved
                }
            }
            ServerAutoContextOutcome(context, candidates.size, plannedMoved, attempted, attemptedMoved,
                verifiedSuccesses, measuredFailures, firstEvidence, firstMoved)
        }
}
