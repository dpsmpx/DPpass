package com.dpsmpx.dppass.app

import android.net.ConnectivityManager
import android.net.LocalSocket
import android.net.Network

/**
 * Receives a private descriptor on a connected app-owned socket. A caller
 * must establish the exact helper identity and exclusive creation before
 * invoking this adapter. It does not launch a ROOT process, bind a listener,
 * install routes, or enable forwarding. No production caller yet.
 */
internal object RootHotspotAndroidTun {
    fun receive(
        socket: LocalSocket,
        expected: RootHotspotTunLifetime.Identity,
        mtu: Int,
        physicalNetwork: Network,
        connectivity: ConnectivityManager,
        inventory: RootHotspotInventoryObserver,
        helperRetired: () -> Boolean,
    ): RootHotspotTunLifetime {
        require(mtu in 576..1500)
        val descriptor = RootHotspotTunReceiver.receive(socket, expected.name)
        try {
            // The engine owner retains the returned descriptor even when
            // constructing TunInput later fails. No native start here.
            check(expected.present(inventory.stableInventory())) {
                "ROOT hotspot TUN inventory does not match helper identity"
            }
            return RootHotspotTunLifetime(expected,
                inputFactory = { RootHotspotTunInput.create(descriptor, mtu, physicalNetwork, connectivity) },
                closeDescriptor = descriptor::close,
                inventory = inventory::stableInventory,
                helperRetired = helperRetired,
            )
        } catch (failure: Throwable) {
            try {
                descriptor.close()
            } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }
}
