package com.dpsmpx.dppass.app

/**
 * Single-use, privacy-safe final transfer snapshot. Periodic logging can
 * miss a 1–29 second connection that was immediately replaced by the user.
 * JNI desync totals are process-wide; subtract the session's starting values
 * instead of attributing prior sessions' strategies to this connection.
 */
internal class Zapret2FinalCounter(
    private val initialApplied: Long,
    private val initialSkipped: Long,
) {
    private var finished = false

    data class Sample(
        val upBytes: Long,
        val downBytes: Long,
        val appliedDelta: Long,
        val skippedDelta: Long,
        val appliedTotal: Long,
        val skippedTotal: Long,
    )

    @Synchronized
    fun finish(upBytes: Long, downBytes: Long, applied: Long, skipped: Long): Sample? {
        if (finished) return null
        finished = true
        return Sample(
            upBytes = upBytes.coerceAtLeast(0L),
            downBytes = downBytes.coerceAtLeast(0L),
            appliedDelta = (applied - initialApplied).coerceAtLeast(0L),
            skippedDelta = (skipped - initialSkipped).coerceAtLeast(0L),
            appliedTotal = applied.coerceAtLeast(0L),
            skippedTotal = skipped.coerceAtLeast(0L),
        )
    }
}
