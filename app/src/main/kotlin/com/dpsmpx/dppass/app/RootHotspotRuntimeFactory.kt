package com.dpsmpx.dppass.app

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Process
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.xray.XrayProxyEngine

/**
 * Experimental composition only. Callers MUST provide independent AP
 * ownership, offload and traffic proof; no default accepting provider.
 * Use the existing AppGraph engine instance, not another native runtime.
 * No registration, automatic start or process recovery.
 */
internal object RootHotspotRuntimeFactory {
    fun create(
        context: Context,
        request: RootHotspotLifecycle.Request,
        root: RootHotspotRootAccess,
        slot: RootHotspotNetworkSlot,
        wifi: WifiManager,
        handler: Handler,
        sharedEngine: XrayProxyEngine,
        physicalNetwork: Network,
        connectivity: ConnectivityManager,
        mtu: Int,
        config: (RootHotspotAdmission.Session) -> CompiledConfig?,
        ownerEvidence: () -> RootHotspotPlatformObservationSource.OwnerEvidence?,
        proof: RootHotspotEngineDriver.Proof<WifiManager.LocalOnlyHotspotReservation>,
        notifyStopped: (RootHotspotLifecycle.Request) -> Unit,
    ): RootHotspotServiceRuntime<WifiManager.LocalOnlyHotspotReservation> {
        require(mtu in 576..1500)
        val app = context.applicationContext
        val inventory = root.inventory()
        val platform = RootHotspotPlatformObservationSource(request, root.tethering(), inventory, ownerEvidence)
        val gate = RootHotspotPlatformGate<WifiManager.LocalOnlyHotspotReservation>(request, inventory, platform::observe)
        val ap = RootHotspotAndroidAccessPoint(wifi, handler, gate, { notifyStopped(request) }, platform)
        val guardedProof = object : RootHotspotEngineDriver.Proof<WifiManager.LocalOnlyHotspotReservation> {
            override fun platformSafe(resource: WifiManager.LocalOnlyHotspotReservation,
                                      identity: RootHotspotInterfaceEvidence.Identity): Boolean =
                gate.discover(resource) == identity &&
                    RootHotspotTunInput.isPhysical(physicalNetwork, connectivity) &&
                    proof.platformSafe(resource, identity)

            override fun guard(plan: RootHotspotNetworkPlan) = proof.guard(plan)
            override fun evidence(plan: RootHotspotNetworkPlan) = proof.evidence(plan)
            override fun attached(plan: RootHotspotNetworkPlan) = proof.attached(plan)
        }
        val egress = RootHotspotBoundEgress<WifiManager.LocalOnlyHotspotReservation>(request) { bound, plan ->
            val driver = RootHotspotEngineDriver(RootHotspotEngineOwner.shared(sharedEngine),
                config, { _, selected ->
                    check(selected === plan)
                    RootHotspotTunAcquirer.acquire(app, root, bound, selected.identity.session,
                        physicalNetwork, connectivity, mtu)
                }, guardedProof)
            RootHotspotEgressCoordinator({ identity ->
                require(identity == plan.identity)
                plan
            }, driver, root.firewall(), root.routing())
        }
        return RootHotspotServiceRuntime(request, root, {
            RootOwnerIdentity(Process.myPid(), RootProcessIdentity.currentAppStartTime())
        }, slot, ap, egress)
    }
}
