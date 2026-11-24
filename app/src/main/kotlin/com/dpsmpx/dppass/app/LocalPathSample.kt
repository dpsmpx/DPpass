package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.TrafficStats

/** Terminal outbound counters only. Not application content or TUN attribution. */
internal data class LocalPathSample(val proxy: TrafficStats, val all: TrafficStats) {
    fun deltaFrom(before: LocalPathSample): LocalPathDelta? {
        val pu = proxy.uplinkBytes - before.proxy.uplinkBytes
        val pd = proxy.downlinkBytes - before.proxy.downlinkBytes
        val au = all.uplinkBytes - before.all.uplinkBytes
        val ad = all.downlinkBytes - before.all.downlinkBytes
        // Independent snapshots may race a counter update. Do not fabricate
        // an exact partition if a reset or inconsistent read is observed.
        if (pu < 0 || pd < 0 || au < pu || ad < pd) return null
        return LocalPathDelta(pu, pd, au - pu, ad - pd)
    }
}
internal data class LocalPathDelta(val proxyUp: Long, val proxyDown: Long,
    val otherUp: Long, val otherDown: Long)
