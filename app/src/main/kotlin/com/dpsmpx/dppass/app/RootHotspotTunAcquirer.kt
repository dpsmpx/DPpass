package com.dpsmpx.dppass.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.os.Process

/**
 * Compose signed helper staging, exact claim launch, bounded private
 * listener and descriptor ownership. Caller must be the sole worker and
 * hold the bound live claim; this adapter does not configure or raise TUN,
 * start Xray, install forwarding or register a service.
 */
internal object RootHotspotTunAcquirer {
    fun acquire(context: Context, root: RootHotspotRootAccess, claim: RootHotspotClaim,
                session: RootHotspotAdmission.Session, physicalNetwork: Network,
                connectivity: ConnectivityManager, mtu: Int): RootHotspotTunLifetime {
        require(mtu in 576..1500)
        val staged = checkNotNull(RootPidfdDeployment.stage(context)) { "ROOT hotspot helper unavailable" }
        val handoff = RootHotspotTunHandoff(
            open = { RootHotspotTunSocket.open(context) },
            launch = { endpoint ->
                root.launchTun(claim.tunLaunch(endpoint.path.absolutePath, Process.myUid(),
                    staged.file.absolutePath, staged.digest))
            },
            receive = { endpoint, receipt ->
                endpoint.accept().use { peer ->
                    check(root.execute(claim.tunHelperRetired(receipt))) { "ROOT hotspot helper retirement unconfirmed" }
                    RootHotspotAndroidTun.receive(peer, receipt, mtu, physicalNetwork, connectivity,
                        root.inventory(), { root.execute(claim.tunHelperRetired(receipt)) })
                }
            },
            discard = staged::discard,
        )
        return handoff.acquire(session)
    }
}
