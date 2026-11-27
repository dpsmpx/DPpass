package com.dpsmpx.dppass.app

/**
 * Explicit recovery coordinator. No automatic removal or process signals.
 * Only a trusted independent proof provider may authorize cleanup of the
 * exact observed orphan. A false or ambiguous result retains the block.
 */
internal class RootHotspotRecovery(
    private val inspect: () -> RootHotspotRootAccess.ClaimState,
    private val reconstruct: (RootHotspotOwnerRecord) -> RootHotspotClaim,
    private val execute: (String) -> Boolean,
) {
    enum class Outcome { ABSENT, UNKNOWN, OWNER_UNCONFIRMED, EVIDENCE_REQUIRED, CLEANUP_PENDING, RECOVERED }

    /** The cleanup script must independently verify AP request retirement,
     * egress termination and owned resources inside the recovery transaction.
     * Null means proof is unavailable, never permission to remove metadata. */
    fun recover(helperPath: String?, verifiedCleanup: (RootHotspotOwnerRecord) -> String?): Outcome {
        return try {
            when (val state = inspect()) {
                RootHotspotRootAccess.ClaimState.Absent -> Outcome.ABSENT
                RootHotspotRootAccess.ClaimState.Unknown -> Outcome.UNKNOWN
                is RootHotspotRootAccess.ClaimState.Present -> {
                    val record = state.record
                    val claim = reconstruct(record)
                    if (!execute(claim.confirmOrphan(helperPath))) return Outcome.OWNER_UNCONFIRMED
                    val body = verifiedCleanup(record)?.takeIf { it.isNotBlank() }
                        ?: return Outcome.EVIDENCE_REQUIRED
                    if (inspect() != state) return Outcome.CLEANUP_PENDING
                    if (!execute(claim.recoverAfter(body, helperPath))) return Outcome.CLEANUP_PENDING
                    if (inspect() == RootHotspotRootAccess.ClaimState.Absent) Outcome.RECOVERED
                    else Outcome.CLEANUP_PENDING
                }
            }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            Outcome.CLEANUP_PENDING
        } catch (_: Exception) {
            Outcome.CLEANUP_PENDING
        }
    }
}
