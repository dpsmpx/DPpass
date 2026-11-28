package com.dpsmpx.dppass.app

/** A diagnostic may not mix observations from different native or Android networks. */
@ConsistentCopyVisibility
internal data class DptsSession private constructor(
    val network: String,
    val handle: Long,
    val generation: Long,
    val offline: Boolean = false,
) {
    companion object {
        /** Only a stable Idle revision can own an offline loopback diagnostic. */
        fun offline(snapshot: TunnelState.StatusSnapshot, generation: Long?): DptsSession? =
            if (snapshot.status == TunnelStatus.Idle && generation != null && generation >= 0)
                DptsSession("LOCAL", snapshot.revision, generation, offline = true) else null

        fun capture(network: String, handle: Long?, generation: Long?): DptsSession? {
            if (handle == null || generation == null || generation < 0) return null
            return DptsSession(network, handle, generation)
        }
    }
}
