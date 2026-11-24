package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ModelNumericFieldsTest {
    @Test
    fun countersRequireIntegralNumbersWithinBounds() {
        for (value in listOf(0, 1, 42L, 1_000_000_000L)) {
            assertTrue(ModelNumericFields.observation(value))
        }
        for (value in listOf(null, true, "42", 42.0, 0.5, -1, 1_000_000_001L, Double.NaN)) {
            assertFalse(ModelNumericFields.observation(value))
        }
    }

    @Test
    fun weightsRejectCoercionsAndNonfiniteValues() {
        for (value in listOf(-4, 0L, 0.125, 4.0)) assertTrue(ModelNumericFields.weight(value))
        for (value in listOf(null, true, "0.1", 4.01, -4.01, Double.NaN, Double.POSITIVE_INFINITY)) {
            assertFalse(ModelNumericFields.weight(value))
        }
    }

    @Test
    fun sparseKeysUseOneDecimalSpellingAndRespectCapacity() {
        assertEquals(0L, ModelNumericFields.sparseIndex("0", 10))
        assertEquals(9L, ModelNumericFields.sparseIndex("9", 10))
        for (key in listOf("", "00", "01", "+1", "-0", "-1", "10", "1.0", " 1", "9223372036854775808")) {
            assertNull(ModelNumericFields.sparseIndex(key, 10))
        }
        assertNull(ModelNumericFields.sparseIndex("0", 0))
    }
}
