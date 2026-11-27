package com.dpsmpx.dppass.app

/**
 * Read-only, deliberately restrictive AOSP offload diagnostic. An explicitly
 * disabled HAL and BPF configuration is a necessary policy condition, not
 * sufficient proof of absence of vendor, kernel or stale forwarding paths.
 * Do not log the dump or change system settings.
 */
internal object RootHotspotOffloadEvidence {
    enum class Hardware { DISABLED, STOPPED, STARTED, UNKNOWN }
    enum class Bpf { DISABLED, ENABLED, UNKNOWN }

    data class Snapshot(
        val tether: RootHotspotTetherState.Snapshot,
        val hardware: Hardware,
        val bpf: Bpf,
    ) {
        val explicitlyDisabled: Boolean
            get() = hardware == Hardware.DISABLED && bpf == Bpf.DISABLED

        fun allowsObservation(identity: RootHotspotInterfaceEvidence.Identity): Boolean =
            explicitlyDisabled && tether.isolatedLocalOnly == identity.name
    }

    fun parse(raw: String): Snapshot? {
        val tether = RootHotspotTetherState.parse(raw) ?: return null
        val lines = raw.lines().map { it.trim() }
        if (lines.any { it.startsWith("Error dumping") || it.startsWith("Dump timeout") ||
                it.startsWith("Permission Denial") }) return null
        val hardwareAt = lines.indexOf("Hardware offload:")
        val bpfAt = lines.indexOf("BPF offload:")
        val logAt = lines.indexOf("Log:")
        if (hardwareAt < 0 || logAt <= hardwareAt ||
            lines.count { it == "Hardware offload:" } != 1 ||
            lines.count { it == "BPF offload:" } > 1) return null
        if (bpfAt >= 0 && (bpfAt <= hardwareAt || bpfAt >= logAt)) return null
        val hw = lines.subList(hardwareAt + 1, if (bpfAt >= 0) bpfAt else logAt)
            .filter { it.isNotEmpty() }
        val hardware = when {
            hw == listOf("Offload disabled") -> Hardware.DISABLED
            hw.firstOrNull() == "Offload HALs not started" &&
                hw.none { it == "Offload disabled" || it == "Offload HALs started" } -> Hardware.STOPPED
            hw.firstOrNull() == "Offload HALs started" -> Hardware.STARTED
            else -> Hardware.UNKNOWN
        }
        val bpf = if (bpfAt < 0) Bpf.UNKNOWN else {
            val rows = lines.subList(bpfAt + 1, logAt).filter { it.isNotEmpty() }
            val flag = rows.filter { it.startsWith("mIsBpfEnabled:") }
            val polling = rows.filter { it.startsWith("Polling ") && !it.startsWith("Polling interval:") }
            when {
                flag == listOf("mIsBpfEnabled: true") && rows.firstOrNull() == flag.single() -> Bpf.ENABLED
                flag == listOf("mIsBpfEnabled: false") &&
                    rows.take(2) == listOf("mIsBpfEnabled: false", "Polling not started") &&
                    polling == listOf("Polling not started") -> Bpf.DISABLED
                else -> Bpf.UNKNOWN
            }
        }
        return Snapshot(tether, hardware, bpf)
    }

    class Observer(private val execute: (List<String>) -> RootCommandRunner.CompleteResult) {
        private fun sample(): Snapshot? {
            val result = execute(listOf("dumpsys", "tethering", "--short"))
            return if (result.exitCode == 0) parse(result.stdout) else null
        }

        fun stable(): Snapshot? = try {
            val first = sample()
            val second = sample()
            first?.takeIf { it == second }
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) { null }

        /** Necessary veto only. Caller still needs independent traffic
         * and AP ownership evidence for the exact current session. */
        fun allows(identity: RootHotspotInterfaceEvidence.Identity): Boolean =
            stable()?.allowsObservation(identity) == true
    }
}
