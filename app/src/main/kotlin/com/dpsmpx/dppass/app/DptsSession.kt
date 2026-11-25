package com.dpsmpx.dppass.app

/** A diagnostic may not mix observations from different native or Android networks. */
@ConsistentCopyVisibility
internal data class DptsSession private constructor(
    val network: String,
    val handle: Long,
    val generation: Long,
) {
    companion object {
        fun capture(network: String, handle: Long?, generation: Long?): DptsSession? {
            if (handle == null || generation == null || generation < 0) return null
            return DptsSession(network, handle, generation)
        }
    }
}
