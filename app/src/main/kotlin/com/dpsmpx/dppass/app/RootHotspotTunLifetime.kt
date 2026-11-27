package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.engine.TunInput

/** Exact private TUN identity and retirement. The caller must independently
 * establish creation by its own helper; an interface name alone is not proof.
 * Never delete an interface by name. */
internal class RootHotspotTunLifetime(
    val identity: Identity,
    private val inputFactory: () -> TunInput,
    private val closeDescriptor: () -> Unit,
    private val inventory: () -> RootHotspotInterfaceEvidence.Inventory?,
    private val helperRetired: () -> Boolean,
    private val linkHealthy: () -> Boolean = { true },
) : RootHotspotEngineOwner.Tun {
    data class Identity(val session: RootHotspotAdmission.Session, val name: String, val index: Int) {
        init {
            require(name.matches(Regex("[a-zA-Z0-9_][a-zA-Z0-9_-]{0,14}")) && name != "lo")
            require(index > 0 && index != session.downstreamIndex)
        }

        fun present(observed: RootHotspotInterfaceEvidence.Inventory?): Boolean =
            observed != null && observed.indexOf(name) == index &&
                observed.nameOf(index) == name && observed.ipv4(name).isEmpty()

        fun absent(observed: RootHotspotInterfaceEvidence.Inventory?): Boolean =
            observed != null && observed.indexOf(name) == null && observed.nameOf(index) == null
    }

    private var closing = false
    private var closed = false
    private var cached: TunInput? = null

    override val input: TunInput
        get() {
            check(!closing) { "ROOT hotspot TUN already closing" }
            check(identity.present(inventory())) { "ROOT hotspot TUN identity changed" }
            return cached ?: inputFactory().also { cached = it }
        }

    override fun healthy(): Boolean = !closing && cached != null && identity.present(inventory()) && linkHealthy()

    /** Retry only the same descriptor object, never a saved numeric fd. */
    override fun close() {
        if (closed) return
        closing = true
        closeDescriptor()
        cached = null
        closed = true
    }

    override fun verifyClosed(): Boolean {
        if (!closed) return false
        return try {
            helperRetired() && identity.absent(inventory()) && helperRetired() &&
                identity.absent(inventory())
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Exception) { false }
    }
}
