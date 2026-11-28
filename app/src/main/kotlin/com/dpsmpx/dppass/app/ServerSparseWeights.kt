package com.dpsmpx.dppass.app

import kotlin.math.abs

/** Хранит веса каждой головы в порядке последнего обновления, от старых к новым. */
internal class ServerSparseWeights(capacity: Long, weights: Map<Long, Double>, recency: List<Long>?) {
    private val quotas = IntArray(ServerContextHead.CONTEXTS) { quota(it, capacity) }
    private val heads = Array(ServerContextHead.CONTEXTS) { LinkedHashMap<Long, Double>() }

    init {
        // В старых V4 порядок неизвестен. При первом обучении сохраняем
        // веса с наибольшим модулем, разрешая равенство по индексу.
        val order = recency ?: weights.entries.sortedWith(compareBy({ abs(it.value) }, { it.key })).map { it.key }
        for (index in order) put(index, weights.getValue(index))
    }

    fun weight(index: Long): Double = heads[ServerContextHead.sparseContext(index)][index] ?: 0.0

    fun learn(features: Map<Long, Double>, delta: Double) {
        val (known, novel) = features.entries.partition { (index, _) ->
            heads[ServerContextHead.sparseContext(index)].containsKey(index)
        }
        // Сначала обновляем использованные веса, чтобы новые признаки этой
        // же попытки не вытеснили их до обновления.
        for ((index, feature) in known) put(index, ServerContextHead.update(weight(index), delta * 0.2, feature))
        for ((index, feature) in novel) put(index, ServerContextHead.update(0.0, delta * 0.2, feature))
    }

    fun entries(): Sequence<Map.Entry<Long, Double>> = heads.asSequence().flatMap { it.entries.asSequence() }

    private fun put(index: Long, weight: Double) {
        val context = ServerContextHead.sparseContext(index)
        val head = heads[context]
        val quota = quotas[context]
        if (head.remove(index) == null && head.size == quota) {
            val oldest = head.keys.iterator()
            oldest.next()
            oldest.remove()
        }
        head[index] = weight
    }

    companion object {
        fun quota(context: Int, capacity: Long): Int = ServerContextHead.sparseSlots(
            context, minOf(capacity, Zapret2NeuralModel.MAX_SPARSE_ENTRIES.toLong()),
        ).toInt()
    }
}
