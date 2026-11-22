package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Pure dimension planning: never allocate a 100M-element tensor. */
class NeuralParameterArchitectureTest {
    @Test
    fun sparseBudgetFitsOneOrTwoLayerCoreForBothModels() {
        for (kind in Zapret2NeuralModel.Kind.entries) {
            val minimum = Zapret2NeuralModel.minParameters(kind)
            for (budget in listOf(minimum, 100_000L, 100_000_000L, 1_000_000_000L)) {
                val (first, deeper) = Zapret2NeuralModel.architecture(kind, budget)
                assertTrue(first in 8..1024)
                assertTrue(deeper in 0..512)
                val last = if (deeper > 0) deeper else first
                val allocated = first.toLong() * 9 +
                    deeper.toLong() * (first + 1) +
                    kind.outputs.toLong() * (last + 1) +
                    kind.contexts.toLong() * kind.outputs
                assertTrue(allocated <= budget, "Dense tensor exceeds budget for $kind")
                if (budget >= 100_000L) assertTrue(deeper > 0)
            }
        }
    }

    @Test
    fun unsafeNumbersAreRefusedBeforeModelAllocation() {
        for (kind in Zapret2NeuralModel.Kind.entries) {
            assertFailsWith<IllegalArgumentException> {
                Zapret2NeuralModel.architecture(kind,
                    Zapret2NeuralModel.minParameters(kind) - 1)
            }
            assertFailsWith<IllegalArgumentException> {
                Zapret2NeuralModel.architecture(kind, 1_000_000_001L)
            }
            assertEquals(128 to 64,
                Zapret2NeuralModel.architecture(kind, 100_000_000L))
        }
    }
}
