package com.dpsmpx.dppass.app

import kotlin.math.exp

/** One independent trainable server head over the frozen feature extractor. */
internal object ServerContextHead {
    const val CONTEXTS = 6
    private const val LR = 0.035

    fun probability(weights: DoubleArray, bias: Double, features: DoubleArray, sparseLogit: Double): Double {
        require(weights.size == features.size)
        var z = bias + sparseLogit
        for (i in features.indices) z += weights[i] * features[i]
        return 1.0 / (1.0 + exp((-z).coerceIn(-12.0, 12.0)))
    }

    fun delta(label: Double, probability: Double): Double {
        require(label == 0.0 || label == 1.0)
        require(probability.isFinite() && probability in 0.0..1.0)
        return LR * (label - probability)
    }

    fun update(weight: Double, delta: Double, feature: Double): Double =
        (weight + delta * feature).coerceIn(-4.0, 4.0)

    /** Disjoint interleaved indices within the total sparse parameter budget. */
    fun sparseIndex(context: Int, capacity: Long, hash: Long): Long? {
        require(context in 0 until CONTEXTS && capacity in 0..1_000_000_000L && hash >= 0)
        val slots = sparseSlots(context, capacity)
        if (slots == 0L) return null
        return context + CONTEXTS * (hash % slots)
    }

    fun sparseSlots(context: Int, capacity: Long): Long =
        capacity / CONTEXTS + if (context < capacity % CONTEXTS) 1L else 0L

    fun sparseContext(index: Long): Int = (index % CONTEXTS).toInt()
}
