package com.dpsmpx.dppass.app

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ServerSparseWeightsTest {
    @Test fun quotasShareTheStorageLimitAndRespectSmallHashSpaces() {
        for (capacity in listOf(0L, 1L, 5L, 6L, 31L, 4095L, 4096L, 4097L, 1_000_000_000L)) {
            val quotas = List(ServerContextHead.CONTEXTS) { ServerSparseWeights.quota(it, capacity) }
            assertEquals(minOf(capacity, Zapret2NeuralModel.MAX_SPARSE_ENTRIES.toLong()).toInt(), quotas.sum())
            assertTrue(quotas.max() - quotas.min() <= 1)
            for ((context, quota) in quotas.withIndex()) {
                assertTrue(quota <= ServerContextHead.sparseSlots(context, capacity))
            }
        }
    }

    @Test fun fullHeadAdmitsNewExperienceWithoutUsingAnotherHeadsCapacity() {
        val store = ServerSparseWeights(10_000, emptyMap(), null)
        val quota = ServerSparseWeights.quota(0, 10_000)
        repeat(quota) { store.learn(mapOf(it * 6L to 1.0), 1.0) }
        store.learn(mapOf(1L to 1.0), -1.0)
        val incoming = quota * 6L
        // Новый индекс указан раньше существующего, самого старого в голове.
        store.learn(linkedMapOf(incoming to 1.0, 0L to 1.0), 1.0)
        assertEquals(0.4, store.weight(0))
        assertEquals(0.0, store.weight(6))
        assertEquals(0.2, store.weight(incoming))
        assertEquals(-0.2, store.weight(1))
        assertEquals(quota + 1, store.entries().count())
    }

    @Test fun recencySurvivesReloadAndScoringDoesNotRefreshIt() {
        val capacity = 10_000L
        val quota = ServerSparseWeights.quota(0, capacity)
        val before = ServerSparseWeights(capacity, emptyMap(), null)
        repeat(quota) { before.learn(mapOf(it * 6L to 1.0), 1.0) }
        before.learn(mapOf(0L to 1.0), 1.0)
        val snapshot = before.entries().associate { it.key to it.value }
        // Порядок свойств JSON-объекта может отличаться от порядка обновлений.
        val after = ServerSparseWeights(capacity, snapshot.toSortedMap(), snapshot.keys.toList())
        assertEquals(0.2, after.weight(6))
        after.learn(mapOf(quota * 6L to 1.0), 1.0)
        assertEquals(0.4, after.weight(0))
        assertEquals(0.0, after.weight(6))
        assertEquals(0.2, after.weight(12))
    }

    @Test fun olderV4WeightsAreTrimmedByMagnitudeThenIndex() {
        val capacity = 10_000L
        val quota = ServerSparseWeights.quota(0, capacity)
        val weights = (0..quota + 1).associate { it * 6L to -0.5 } + mapOf(0L to -2.0, 1L to 0.1)
        val store = ServerSparseWeights(capacity, weights, null)
        assertEquals(-2.0, store.weight(0))
        assertEquals(0.0, store.weight(6))
        assertEquals(0.0, store.weight(12))
        assertEquals(-0.5, store.weight(18))
        assertEquals(0.1, store.weight(1))
        assertEquals(quota + 1, store.entries().count())
    }
}
