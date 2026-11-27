package com.dpsmpx.dppass.app

/**
 * Read-only evidence from Android tethering service, not a public API.
 * Accept the narrow AOSP dump shape only; unknown vendor shapes fail closed.
 * Do not log or persist the full dump. It can contain private network details.
 * This identifies platform state, not the owner of a Wi-Fi request.
 */
internal object RootHotspotTetherState {
    enum class State { LOCAL_ONLY, TETHERED, AVAILABLE, UNAVAILABLE }
    data class Snapshot(
        val interfaces: Map<String, State>,
        val upstreamWanted: Boolean,
        val currentUpstream: String,
    ) {
        val localOnly: Set<String> get() = interfaces.filterValues { it == State.LOCAL_ONLY }.keys
        private val noUpstream: Boolean get() = !upstreamWanted && currentUpstream == "null"
        val idle: Boolean get() = noUpstream && interfaces.values.none {
            it == State.LOCAL_ONLY || it == State.TETHERED
        }

        /** Global candidate only. Does not establish request ownership or
         * absence of hardware/software offload. */
        val isolatedLocalOnly: String? get() =
            localOnly.singleOrNull()?.takeIf { noUpstream && State.TETHERED !in interfaces.values }
    }

    private val row = Regex("([a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}) - (LocalHotspotState|TetheredState|AvailableState|UnavailableState) - lastError = 0")
    private val upstream = Regex("Upstream wanted: (true|false)")

    fun parse(raw: String): Snapshot? {
        if (raw.length > 256 * 1024 || !raw.endsWith('\n') ||
            raw.any { it == '\u0000' || it == '\r' }) return null
        val lines = raw.lines().map { it.trim() }
        if (lines.any { it.startsWith("Permission Denial") || it.startsWith("Dump timeout") ||
                it.startsWith("Can't find service") }) return null
        if (lines.count { it == "Tethering:" } != 1 ||
            lines.count { it == "Tether state:" } != 1) return null
        val start = lines.indexOf("Tether state:")
        if (lines.indexOf("Tethering:") >= start) return null
        val end = lines.indexOfFirst { upstream.matches(it) }
        if (end <= start || lines.count { upstream.matches(it) } != 1) return null
        val upstreamLine = lines.getOrNull(end + 1) ?: return null
        val prefix = "Current upstream interface(s): "
        if (!upstreamLine.startsWith(prefix) || lines.getOrNull(end + 2) != "Hardware offload:") return null
        val currentUpstream = upstreamLine.removePrefix(prefix)
        if (currentUpstream.isBlank() || currentUpstream.length > 1024) return null
        val log = lines.indexOf("Log:")
        if (log <= end + 2 || lines.count { it == "Log:" } != 1) return null
        // --short must finish with the explicit AOSP sentinel. A header
        // alone can be a truncated dump, not evidence that no AP exists.
        if (lines.getOrNull(log + 1) != "<log removed for brevity>" ||
            lines.drop(log + 2).any { it.isNotEmpty() }) return null
        val states = linkedMapOf<String, State>()
        for (line in lines.subList(start + 1, end)) {
            val match = row.matchEntire(line) ?: return null
            val name = match.groupValues[1]
            if (name == "lo") return null
            val state = when (match.groupValues[2]) {
                "LocalHotspotState" -> State.LOCAL_ONLY
                "TetheredState" -> State.TETHERED
                "AvailableState" -> State.AVAILABLE
                "UnavailableState" -> State.UNAVAILABLE
                else -> return null
            }
            if (states.put(name, state) != null) return null
        }
        return Snapshot(states.toMap(), lines[end] == "Upstream wanted: true", currentUpstream)
    }
}

/** Independent read-only observation, with a bounded complete-output executor.
 * Two identical snapshots are required; this is not an atomic observation. */
internal class RootHotspotTetherObserver(
    private val execute: (List<String>) -> RootCommandRunner.CompleteResult,
) {
    fun stable(): RootHotspotTetherState.Snapshot? = try {
        val first = read()
        val second = read()
        first?.takeIf { it == second }
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
        null
    } catch (_: Exception) {
        null
    }

    private fun read(): RootHotspotTetherState.Snapshot? {
        val result = execute(listOf("dumpsys", "tethering", "--short"))
        return if (result.exitCode == 0) RootHotspotTetherState.parse(result.stdout) else null
    }
}
