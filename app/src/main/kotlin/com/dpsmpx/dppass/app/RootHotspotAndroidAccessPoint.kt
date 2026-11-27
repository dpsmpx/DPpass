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
) {
    fun dispatch(pending: RootHotspotReservation<WifiManager.LocalOnlyHotspotReservation>) {
        check(Looper.myLooper() != handler.looper) { "ROOT hotspot worker must not block callback looper" }
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

    fun release(resource: WifiManager.LocalOnlyHotspotReservation) {
        resource.close()
        gate.released(resource)
    }

    fun discover(resource: WifiManager.LocalOnlyHotspotReservation) = gate.discover(resource)
    fun verifyStopped(identity: RootHotspotInterfaceEvidence.Identity?) = gate.stopped(identity)
}
