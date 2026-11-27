package com.dpsmpx.dppass.app

import java.io.Closeable

/**
 * One synchronous handoff. Close the listener and staged copy even on
 * ambiguous launch failure; never retry a launch. The returned descriptor
 * belongs to the engine owner. Closing a listener does not establish that
 * the helper or TUN is retired.
 */
internal class RootHotspotTunHandoff<T : Closeable, R : RootHotspotEngineOwner.Tun>(
    private val open: () -> T,
    private val launch: (T) -> RootHotspotTunLaunch.Receipt?,
    private val receive: (T, RootHotspotTunLaunch.Receipt) -> R,
    private val discard: () -> Unit,
) {
    private var attempted = false

    fun acquire(session: RootHotspotAdmission.Session): R {
        check(!attempted)
        attempted = true
        var result: R? = null
        try {
            open().use { endpoint ->
                val receipt = checkNotNull(launch(endpoint)) { "ROOT hotspot TUN launch unconfirmed" }
                check(receipt.identity.session == session) { "ROOT hotspot TUN receipt belongs to another session" }
                result = receive(endpoint, receipt)
            }
            discard()
            return checkNotNull(result)
        } catch (failure: Throwable) {
            // If closing the endpoint fails after receipt, do not lose
            // the descriptor silently. The engine has not started yet.
            result?.let { acquired ->
                try { acquired.close() } catch (cleanup: Throwable) {
                    if (cleanup !== failure) failure.addSuppressed(cleanup)
                }
            }
            try { discard() } catch (cleanup: Throwable) {
                if (cleanup !== failure) failure.addSuppressed(cleanup)
            }
            throw failure
        }
    }
}
