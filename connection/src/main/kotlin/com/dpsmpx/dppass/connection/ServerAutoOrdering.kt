package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.ProfileId

/** Probability and measured observations for the candidate's own context. */
data class ServerAutoScore(val probability: Double, val observations: Long)

/** Optional neural ordering is strictly subordinate to the candidate planner. */
object ServerAutoOrdering {
    private const val MIN_OBSERVATIONS = 4L
    private const val MIN_ADVANTAGE = 0.003

    private fun eligiblePair(
        left: PlannedAttempt, right: PlannedAttempt,
        health: (ProfileId) -> CandidateHealth, lastGood: ProfileId?,
    ): Boolean {
        val a = left.profile
        val b = right.profile
        if (a.id == b.id || a.id == lastGood || b.id == lastGood ||
            a.transportClass != b.transportClass || a.hints.priority != b.hints.priority) return false
        val ah = health(a.id).state
        return ah != HealthState.FAILED && ah == health(b.id).state
    }

    private fun valid(score: ServerAutoScore): Boolean =
        score.probability.isFinite() && score.probability in 0.0..1.0 &&
            score.observations >= MIN_OBSERVATIONS

    /** Use original scores and slots; never bubble a candidate across the plan. */
    fun rank(
        original: ConnectionPlan, scores: List<ServerAutoScore>,
        health: (ProfileId) -> CandidateHealth, lastGood: ProfileId?,
    ): ConnectionPlan {
        if (original.attempts.size != scores.size || original.attempts.size < 2) return original
        val ordered = original.attempts.toMutableList()
        var changed = false
        var i = 0
        while (i + 1 < ordered.size) {
            if (eligiblePair(original.attempts[i], original.attempts[i + 1], health, lastGood) &&
                valid(scores[i]) && valid(scores[i + 1]) &&
                scores[i + 1].probability - scores[i].probability > MIN_ADVANTAGE) {
                ordered[i] = original.attempts[i + 1]
                ordered[i + 1] = original.attempts[i]
                changed = true
                i += 2
            } else i++
        }
        return if (changed) original.copy(attempts = ordered) else original
    }

    /** Validate the complete attempt payload and exact disjoint adjacent permutation. */
    fun accepts(
        original: ConnectionPlan, candidate: ConnectionPlan,
        health: (ProfileId) -> CandidateHealth, lastGood: ProfileId?,
    ): Boolean {
        if (original.attempts.size != candidate.attempts.size ||
            original.excluded != candidate.excluded || original.verdict != candidate.verdict ||
            original.verdictMessage != candidate.verdictMessage) return false
        var i = 0
        while (i < original.attempts.size) {
            if (original.attempts[i] == candidate.attempts[i]) {
                i++
                continue
            }
            if (i + 1 >= original.attempts.size ||
                original.attempts[i] != candidate.attempts[i + 1] ||
                original.attempts[i + 1] != candidate.attempts[i] ||
                !eligiblePair(original.attempts[i], original.attempts[i + 1], health, lastGood))
                return false
            i += 2
        }
        return true
    }
}
