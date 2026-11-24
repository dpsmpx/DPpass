package com.dpsmpx.dppass.app

/** Metadata from independently validated local snapshots.
 * Keep the original architecture and all recorded observation counters.
 * This is a monotonicity guard, not a proof that equal counters imply
 * identical weights (counters can saturate).
 */
internal data class ModelSnapshotStamp(
    val format: String,
    val seed: String,
    val parameters: Long,
    val hidden: Int,
    val deep: Int,
    val observations: Long,
    val contextCounts: List<Long>,
    val calibrationCounts: List<Long>,
) {
    fun canReplaceWith(next: ModelSnapshotStamp): Boolean {
        if (format != next.format || seed != next.seed ||
            parameters != next.parameters || hidden != next.hidden || deep != next.deep ||
            next.observations < observations) return false
        if (!nondecreasing(contextCounts, next.contextCounts)) return false
        // Optional calibration may appear for the first time; once present
        // it must not disappear or lose any recorded observations.
        return calibrationCounts.isEmpty() ||
            nondecreasing(calibrationCounts, next.calibrationCounts)
    }

    private fun nondecreasing(before: List<Long>, after: List<Long>): Boolean =
        before.size == after.size && before.indices.all { after[it] >= before[it] }
}
