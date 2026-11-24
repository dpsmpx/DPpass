package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModelSnapshotStampTest {
    private val initial = ModelSnapshotStamp(
        "format", "0123456789abcdef", 100_000L, 64, 16, 20L,
        listOf(10L, 5L, 5L), emptyList(),
    )

    @Test
    fun acceptsSameArchitectureAndNondecreasingCounters() {
        assertTrue(initial.canReplaceWith(initial))
        val next = initial.copy(observations = 21L, contextCounts = listOf(11L, 5L, 5L))
        assertTrue(initial.canReplaceWith(next))
        assertTrue(next.canReplaceWith(next.copy(calibrationCounts = listOf(1L, 0L, 0L))))
    }

    @Test
    fun rejectsReplacementArchitectureAndCounterRegression() {
        for (next in listOf(
            initial.copy(seed = "replacement"),
            initial.copy(format = "other"),
            initial.copy(parameters = 200_000L),
            initial.copy(hidden = 128),
            initial.copy(deep = 0),
            initial.copy(observations = 19L),
            initial.copy(observations = 21L, contextCounts = listOf(9L, 7L, 5L)),
            initial.copy(contextCounts = emptyList()),
        )) assertFalse(initial.canReplaceWith(next))
        val calibrated = initial.copy(calibrationCounts = listOf(1L, 2L, 3L))
        assertFalse(calibrated.canReplaceWith(initial))
        assertFalse(calibrated.canReplaceWith(calibrated.copy(calibrationCounts = listOf(2L, 1L, 3L))))
        assertTrue(calibrated.canReplaceWith(calibrated.copy(calibrationCounts = listOf(2L, 2L, 3L))))
    }
}
