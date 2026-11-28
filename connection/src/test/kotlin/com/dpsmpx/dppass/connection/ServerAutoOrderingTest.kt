package com.dpsmpx.dppass.connection

import com.dpsmpx.dppass.config.transportClass
import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.diagnostics.DiagCode
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ServerAutoOrderingTest {
    private val base = ir("valid-multi.json").profiles.first()
    private val plan = ConnectionPlan(
        (1..4).map { i -> PlannedAttempt(base.copy(id = ProfileId("server-$i")), listOf("slot $i")) },
        emptyList(), null, null,
    )
    private val neutral: (ProfileId) -> CandidateHealth = { CandidateHealth() }
    private fun scores(vararg p: Double) = p.map { ServerAutoScore(it, 4) }
    private fun ids(p: ConnectionPlan) = p.attempts.map { it.profile.id }
    private fun reordered(vararg index: Int) = plan.copy(attempts = index.map { plan.attempts[it] })

    @Test fun swapsAreDisjointAndMoveAtMostOnePosition() {
        val ranked = ServerAutoOrdering.rank(plan, scores(0.1, 0.8, 0.9, 0.95), neutral, null)
        assertEquals(ids(reordered(1, 0, 3, 2)), ids(ranked))
        assertTrue(ServerAutoOrdering.accepts(plan, ranked, neutral, null))
        assertFalse(ServerAutoOrdering.accepts(plan, reordered(1, 2, 3, 0), neutral, null))
    }

    @Test fun coldStartSmallMarginAndInvalidScoresPreserveOriginal() {
        assertSame(plan, ServerAutoOrdering.rank(plan, scores(0.5, 0.501, 0.5, 0.5), neutral, null))
        assertSame(plan, ServerAutoOrdering.rank(plan, scores(0.1, 0.9, 0.1, 0.9).map { it.copy(observations = 3) }, neutral, null))
        assertSame(plan, ServerAutoOrdering.rank(plan, scores(Double.NaN, 0.9, 0.2, Double.POSITIVE_INFINITY), neutral, null))
        assertSame(plan, ServerAutoOrdering.rank(plan, scores(0.1, 2.0, -1.0, 0.9), neutral, null))
        assertSame(plan, ServerAutoOrdering.rank(plan, emptyList(), neutral, null))
    }

    @Test fun lastGoodFailedAndDifferentHealthAreProtected() {
        val last = plan.attempts[0].profile.id
        val failed = plan.attempts[3].profile.id
        val health: (ProfileId) -> CandidateHealth = {
            if (it == failed) CandidateHealth(state = HealthState.FAILED) else CandidateHealth()
        }
        assertSame(plan, ServerAutoOrdering.rank(plan, scores(0.1, 0.9, 0.1, 0.9), health, last))
        assertFalse(ServerAutoOrdering.accepts(plan, reordered(1, 0, 2, 3), health, last))
        assertFalse(ServerAutoOrdering.accepts(plan, reordered(0, 1, 3, 2), health, last))
        val mixed: (ProfileId) -> CandidateHealth = {
            if (it == plan.attempts[0].profile.id) CandidateHealth(state = HealthState.HEALTHY) else CandidateHealth()
        }
        assertFalse(ServerAutoOrdering.accepts(plan, reordered(1, 0, 2, 3), mixed, null))
    }

    @Test fun transportAndPrioritySlotsCannotChange() {
        val other = ir("valid-multi.json").profiles.first { it.transportClass != base.transportClass }
        val first = plan.attempts[0]
        val second = plan.attempts[1]
        for (protected in listOf(
            second.copy(profile = other),
            second.copy(profile = second.profile.copy(hints = second.profile.hints.copy(priority = base.hints.priority + 1))),
        )) {
            val original = plan.copy(attempts = listOf(first, protected))
            val swapped = original.copy(attempts = original.attempts.reversed())
            assertSame(original, ServerAutoOrdering.rank(original, scores(0.1, 0.9), neutral, null))
            assertFalse(ServerAutoOrdering.accepts(original, swapped, neutral, null))
        }
    }

    @Test fun candidateCannotChangePayloadReasonsExclusionsOrVerdict() {
        val first = plan.attempts.first()
        val modified = listOf(
            plan.copy(attempts = listOf(first.copy(profile = first.profile.copy(name = "changed"))) + plan.attempts.drop(1)),
            plan.copy(attempts = listOf(first.copy(reasons = listOf("changed"))) + plan.attempts.drop(1)),
            plan.copy(attempts = listOf(first, first) + plan.attempts.drop(2)),
            plan.copy(attempts = plan.attempts.drop(1)),
            plan.copy(excluded = listOf(Exclusion(first.profile.id, "changed"))),
            plan.copy(verdict = DiagCode.NO_VIABLE_CANDIDATE),
            plan.copy(verdictMessage = "changed"),
        )
        modified.forEach { assertFalse(ServerAutoOrdering.accepts(plan, it, neutral, null)) }
    }

    @Test fun singleAndEmptyPlansStayIdentical() {
        for (size in 0..1) {
            val original = plan.copy(attempts = plan.attempts.take(size))
            assertSame(original, ServerAutoOrdering.rank(original, List(size) { ServerAutoScore(0.9, 10) }, neutral, null))
            assertTrue(ServerAutoOrdering.accepts(original, original, neutral, null))
        }
    }
}
