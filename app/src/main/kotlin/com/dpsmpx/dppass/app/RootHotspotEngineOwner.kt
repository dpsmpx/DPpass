package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.TunInput
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine

/**
 * Worker-confined owner of a shared Xray lease and exact private TUN.
 * Acquisition is one-shot. An exception during resource acquisition may
 * have created resources; retain the lease instead of guessing absence.
 * The provider must independently confirm closure, not just fd.close().
 */
internal class RootHotspotEngineOwner(private val reserve: () -> Lease?) {
    interface Lease {
        fun start(config: CompiledConfig, input: TunInput): Boolean
        fun stop(): Boolean
        fun releaseAfterTunClosed(verifiedClosed: Boolean): Boolean
    }

    interface Tun {
        val input: TunInput
        /** Must be idempotent for this exact resource, including a failed close response. */
        fun close()
        fun verifyClosed(): Boolean
    }

    private var attempted = false
    private var acquisitionUncertain = false
    private var lease: Lease? = null
    private var tun: Tun? = null
    private var engineStopped = false
    private var tunClosed = false

    fun start(config: CompiledConfig, acquireTun: () -> Tun): Boolean {
        check(!attempted)
        attempted = true
        val reserved = reserve() ?: return false
        lease = reserved
        acquisitionUncertain = true
        val acquired = acquireTun()
        tun = acquired
        acquisitionUncertain = false
        return reserved.start(config, acquired.input)
    }

    /** Keep exact handles on any failure; never close the TUN while native
     * ownership is ambiguous. A successful close is not repeated. */
    fun stop(): Boolean {
        val reserved = lease ?: return !acquisitionUncertain
        if (!engineStopped) {
            if (!reserved.stop()) return false
            engineStopped = true
        }
        if (acquisitionUncertain) return false
        val owned = tun ?: return false
        if (!tunClosed) {
            owned.close()
            tunClosed = true
        }
        if (!owned.verifyClosed() || !reserved.releaseAfterTunClosed(true)) return false
        lease = null
        tun = null
        return true
    }

    fun retired(): Boolean = attempted && lease == null && !acquisitionUncertain

    companion object {
        /** Use AppGraph.graph(context).engine, never a new native runtime. */
        fun shared(engine: XrayProxyEngine): RootHotspotEngineOwner = RootHotspotEngineOwner {
            engine.reserveHotspot()?.let { exact ->
                object : Lease {
                    override fun start(config: CompiledConfig, input: TunInput) = exact.start(config, input)
                    override fun stop() = exact.stop()
                    override fun releaseAfterTunClosed(verifiedClosed: Boolean) =
                        exact.releaseAfterTunClosed(verifiedClosed)
                }
            }
        }
    }
}
