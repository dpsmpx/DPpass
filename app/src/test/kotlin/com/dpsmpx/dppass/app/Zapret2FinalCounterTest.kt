package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class Zapret2FinalCounterTest {
    @Test fun shortSessionReportsDeltaFromProcessBaselineOnlyOnce() {
        val counter = Zapret2FinalCounter(initialApplied = 60, initialSkipped = 11)
        val sample = counter.finish(
            upBytes = 3_654, downBytes = 1_250,
            applied = 67, skipped = 14,
        )!!
        assertEquals(3_654L, sample.upBytes)
        assertEquals(1_250L, sample.downBytes)
        assertEquals(7L, sample.appliedDelta)
        assertEquals(3L, sample.skippedDelta)
        assertEquals(67L, sample.appliedTotal)
        assertEquals(14L, sample.skippedTotal)
        assertNull(counter.finish(9_999, 9_999, 99, 99))
    }

    @Test fun resetOrMissingCountersNeverGenerateNegativeActivity() {
        val counter = Zapret2FinalCounter(initialApplied = 100, initialSkipped = 20)
        val sample = counter.finish(
            upBytes = -10, downBytes = -1,
            applied = 0, skipped = 0,
        )!!
        assertEquals(0L, sample.upBytes)
        assertEquals(0L, sample.downBytes)
        assertEquals(0L, sample.appliedDelta)
        assertEquals(0L, sample.skippedDelta)
    }
}
