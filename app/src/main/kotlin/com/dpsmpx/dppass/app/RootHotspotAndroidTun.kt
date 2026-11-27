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
        receipt: RootHotspotTunLaunch.Receipt,
        mtu: Int,
        physicalNetwork: Network,
        connectivity: ConnectivityManager,
        inventory: RootHotspotInventoryObserver,
        helperRetired: () -> Boolean,
        configure: () -> Boolean,
        linkHealthy: () -> Boolean,
    ): RootHotspotTunLifetime {
        require(mtu in 576..1500)
        val expected = receipt.identity
        val descriptor = RootHotspotTunReceiver.receive(socket, expected.name, receipt.helperPid)
        try {
            // The engine owner retains the returned descriptor even when
            // constructing TunInput later fails. No native start here.
            check(expected.present(inventory.stableInventory())) {
                "ROOT hotspot TUN inventory does not match helper identity"
            }
            return RootHotspotTunLifetime(expected,
                inputFactory = {
                    // EngineOwner already retains the exact descriptor here.
                    check(configure() && linkHealthy()) { "ROOT hotspot TUN setup unconfirmed" }
                    RootHotspotTunInput.create(descriptor, mtu, physicalNetwork, connectivity)
                },
                closeDescriptor = descriptor::close,
                inventory = inventory::stableInventory,
                helperRetired = helperRetired,
                linkHealthy = linkHealthy,
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
