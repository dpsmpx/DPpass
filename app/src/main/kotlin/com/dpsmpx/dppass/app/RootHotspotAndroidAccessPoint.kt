package com.dpsmpx.dppass.app

import android.net.wifi.WifiManager
import android.os.Handler
import android.os.Looper

/**
 * Android callback bridge. The owner supplies an independently validated
 * platform observer; the public LocalOnlyHotspot callback cannot establish
 * kernel interface identity or complete shutdown on its own.
 * Call on a bounded worker separate from the callback looper.
 */
internal class RootHotspotAndroidAccessPoint(
    private val wifi: WifiManager,
    private val handler: Handler,
    private val gate: RootHotspotPlatformGate<WifiManager.LocalOnlyHotspotReservation>,
    private val notifyStopped: () -> Unit,
    private val platform: RootHotspotPlatformObservationSource,
) : RootHotspotServiceRuntime.AccessPoint<WifiManager.LocalOnlyHotspotReservation> {
    override fun dispatch(pending: RootHotspotReservation<WifiManager.LocalOnlyHotspotReservation>) {
        check(Looper.myLooper() != handler.looper) { "ROOT hotspot worker must not block callback looper" }
        check(platform.idleBeforeDispatch()) { "ROOT hotspot platform baseline unconfirmed" }
        gate.dispatched()
        try {
            RootHotspotLocalAccessPoint.request(wifi, handler, pending,
                onStopped = { gate.terminal(); notifyStopped() },
                onStarted = gate::started,
                onFailed = { gate.terminal() },
            )
        } catch (failure: Throwable) {
            gate.dispatchFailed()
            throw failure
        }
    }

    override fun release(resource: WifiManager.LocalOnlyHotspotReservation) {
        resource.close()
        gate.released(resource)
    }

    override fun discover(resource: WifiManager.LocalOnlyHotspotReservation) = gate.discover(resource)
    override fun verifyStopped(identity: RootHotspotInterfaceEvidence.Identity?) = gate.stopped(identity)
}
