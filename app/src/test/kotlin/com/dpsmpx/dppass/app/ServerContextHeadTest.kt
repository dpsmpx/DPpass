package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ServerContextHeadTest {
    @Test fun positiveAndNegativeUpdatesMoveOnlySelectedHead() {
        val features = doubleArrayOf(0.4, 0.8, 0.2)
        val heads = Array(6) { doubleArrayOf(0.1, -0.2, 0.3) }
        val bias = DoubleArray(6)
        fun probability(i: Int) = ServerContextHead.probability(heads[i], bias[i], features, 0.0)
        val before = List(6, ::probability)
        for ((index, label) in listOf(0 to 1.0, 3 to 0.0)) {
            val delta = ServerContextHead.delta(label, probability(index))
            for (i in features.indices) heads[index][i] = ServerContextHead.update(heads[index][i], delta, features[i])
            bias[index] = ServerContextHead.update(bias[index], delta, 1.0)
        }
        assertTrue(probability(0) > before[0])
        assertTrue(probability(3) < before[3])
        for (i in listOf(1, 2, 4, 5)) assertEquals(before[i], probability(i))
    }

    @Test fun sparseSlotsAreDisjointForUnevenAndLargeBudgets() {
        for (capacity in listOf(0L, 1L, 5L, 6L, 7L, 31L, 1_000_000_000L)) {
            for (context in 0..5) {
                for (hash in listOf(0L, 1L, 100L, Long.MAX_VALUE)) {
                    val index = ServerContextHead.sparseIndex(context, capacity, hash)
                    if (context.toLong() >= capacity) assertNull(index)
                    else {
                        requireNotNull(index)
                        assertTrue(index in 0 until capacity)
                        assertEquals(context.toLong(), index % 6)
                    }
                }
            }
        }
    }

    @Test fun clampingAndInvalidArguments() {
        assertEquals(4.0, ServerContextHead.update(3.9, 1.0, 2.0))
        assertEquals(-4.0, ServerContextHead.update(-3.9, -1.0, 2.0))
        assertFailsWith<IllegalArgumentException> { ServerContextHead.delta(1.0, Double.NaN) }
        assertFailsWith<IllegalArgumentException> { ServerContextHead.delta(0.5, 0.4) }
        assertFailsWith<IllegalArgumentException> { ServerContextHead.sparseIndex(6, 100, 1) }
        assertFailsWith<IllegalArgumentException> { ServerContextHead.sparseIndex(0, -1, 1) }
    }
}
