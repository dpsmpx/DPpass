package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ServerLearningWindowTest {
    @Test fun singleCandidateBatchIsConsumedAndCommittedOnce() {
        val window = ServerLearningWindow<Any, List<String>>()
        val token = window.begin()
        val plan = Any()
        assertFalse(window.commitIfCurrent(token) { error("not consumed") })
        assertTrue(window.publish(token, plan, listOf("single")))
        assertFalse(window.publish(token, plan, listOf("duplicate")))
        assertEquals(listOf("single"), window.take(token, plan))
        assertNull(window.take(token, plan))
        assertFalse(window.publish(token, plan, emptyList()))
        var writes = 0
        assertTrue(window.commitIfCurrent(token) { writes++; true })
        assertFalse(window.commitIfCurrent(token) { writes++; true })
        assertEquals(1, writes)
    }

    @Test fun replacedConnectionCannotPublishConsumeOrClearNewBatch() {
        val window = ServerLearningWindow<Any, String>()
        val old = window.begin()
        val oldPlan = Any()
        assertTrue(window.publish(old, oldPlan, "old"))
        val fresh = window.begin()
        val freshPlan = Any()
        assertFalse(window.publish(old, oldPlan, "stale"))
        assertTrue(window.publish(fresh, freshPlan, "fresh"))
        assertNull(window.take(old, freshPlan))
        window.finish(old)
        assertEquals("fresh", window.take(fresh, freshPlan))
        assertFalse(window.commitIfCurrent(old) { error("stale write") })
        assertTrue(window.commitIfCurrent(fresh) { true })
    }

    @Test fun equalButDifferentPlanIsNotAccepted() {
        val window = ServerLearningWindow<List<Int>, String>()
        val token = window.begin()
        val plan = mutableListOf(1)
        assertTrue(window.publish(token, plan, "batch"))
        assertNull(window.take(token, mutableListOf(1)))
        assertNull(window.take(token, plan))
        assertFalse(window.commitIfCurrent(token) { error("wrong plan") })
    }

    @Test fun resetAndCancellationInvalidateBothUnclaimedAndClaimedBatches() {
        for (consume in listOf(false, true)) {
            for (handoff in listOf(false, true)) {
                val window = ServerLearningWindow<Any, String>()
                val token = window.begin()
                val plan = Any()
                assertTrue(window.publish(token, plan, "batch"))
                if (consume) assertEquals("batch", window.take(token, plan))
                if (handoff) window.reset() else window.finish(token)
                assertNull(window.take(token, plan))
                assertFalse(window.publish(token, plan, "stale"))
                assertFalse(window.commitIfCurrent(token) { error("invalidated write") })
            }
        }
    }

    @Test fun failedStorageCannotBeRetriedWithSameEvidence() {
        val window = ServerLearningWindow<Any, String>()
        val token = window.begin()
        val plan = Any()
        assertTrue(window.publish(token, plan, "batch"))
        assertEquals("batch", window.take(token, plan))
        assertFalse(window.commitIfCurrent(token) { false })
        assertFalse(window.commitIfCurrent(token) { error("duplicate write") })
    }
}
