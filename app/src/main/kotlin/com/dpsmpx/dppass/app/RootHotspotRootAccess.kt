package com.dpsmpx.dppass.app

import java.util.UUID

/**
 * Bounded ROOT command boundary for the future hotspot service. Only
 * internal script builders may supply mutation scripts; no user text,
 * credentials or full command output is logged. An exception or nonzero
 * result is ambiguous for a mutation, never proof of absence.
 */
internal class RootHotspotRootAccess(
    private val run: (List<String>, Long) -> RootCommandRunner.CompleteResult =
        { command, timeout -> RootCommandRunner.runComplete(command, timeout) },
    private val timeoutMillis: Long = 15_000,
) {
    init { require(timeoutMillis in 1..60_000) }

    sealed interface ClaimState {
        data object Absent : ClaimState
        data object Unknown : ClaimState
        data class Present(val record: RootHotspotOwnerRecord) : ClaimState
    }

    private fun command(script: String): RootCommandRunner.CompleteResult {
        require(script.isNotBlank() && '\u0000' !in script)
        return run(listOf("su", "-c", "test \"\$(id -u)\" = 0 || exit 1\n" + script), timeoutMillis)
    }

    /** Only fixed inventory commands are allowed through this read path. */
    fun read(args: List<String>): RootCommandRunner.CompleteResult {
        val fixed = args.toList()
        require(fixed in READ_COMMANDS) { "ROOT hotspot unsupported observation" }
        return command(fixed.joinToString(" "))
    }

    /** Trusted internal shell transaction, not an arbitrary command endpoint. */
    fun execute(script: String): Boolean = guarded(false) { command(script).exitCode == 0 }

    fun baseline(): Boolean = guarded(false) {
        val result = command(RootHotspotPreflight.script())
        result.exitCode == 0 && result.stdout == "baseline_available\n"
    }

    /** Read the kernel boot ID through the same verified ROOT command path.
     * PID and start ticks are obtained independently from the app process. */
    fun owner(identity: RootOwnerIdentity): RootHotspotOwner? = guarded<RootHotspotOwner?>(null) {
        val result = read(listOf("cat", "/proc/sys/kernel/random/boot_id"))
        if (result.exitCode != 0) return@guarded null
        val raw = result.stdout
        if (raw.length != 37 || !raw.endsWith('\n')) return@guarded null
        val boot = UUID.fromString(raw.dropLast(1))
        if (boot.toString() + "\n" != raw) return@guarded null
        RootHotspotOwner(identity, boot)
    }

    /** Do not interpret failed inspection, malformed data or a missing lock
     * directory as absence. The acquisition script still checks under flock. */
    fun inspect(): ClaimState = guarded<ClaimState>(ClaimState.Unknown) {
        val result = command(RootHotspotClaim.inspectState())
        if (result.exitCode != 0) return@guarded ClaimState.Unknown
        when {
            result.stdout == "absent\n" -> ClaimState.Absent
            result.stdout.startsWith("present\n") -> RootHotspotOwnerRecord.parse(
                result.stdout.removePrefix("present\n"),
            )?.let { ClaimState.Present(it) } ?: ClaimState.Unknown
            else -> ClaimState.Unknown
        }
    }

    fun inventory() = RootHotspotInventoryObserver(::read)
    fun tethering() = RootHotspotTetherObserver(::read)

    private inline fun <T> guarded(fallback: T, block: () -> T): T = try {
        block()
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        fallback
    } catch (_: Exception) { fallback }

    private companion object {
        val READ_COMMANDS = setOf(
            listOf("ip", "-o", "link", "show"),
            listOf("ip", "-4", "-o", "addr", "show"),
            listOf("dumpsys", "tethering", "--short"),
            listOf("cat", "/proc/sys/kernel/random/boot_id"),
        )
    }
}
