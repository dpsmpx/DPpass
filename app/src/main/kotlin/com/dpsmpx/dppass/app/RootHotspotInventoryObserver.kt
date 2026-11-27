package com.dpsmpx.dppass.app

/**
 * Experimental read-only observation. The platform callback must provide positive,
 * fresh, session-scoped evidence under exclusive ownership; a callback or an
 * unchanged pair of inventories alone cannot prove that an AP is gone.
 * Repeated observations narrow races but are not an atomic kernel snapshot.
 */
internal class RootHotspotInventoryObserver(
    private val execute: (List<String>) -> RootCommandRunner.CompleteResult,
) {
    data class PlatformObservation(
        val session: RootHotspotAdmission.Session,
        val requestRetired: Boolean,
        val state: RootHotspotInterfaceEvidence.PlatformState,
    )

    private fun inventory(): RootHotspotInterfaceEvidence.Inventory? {
        val links = execute(listOf("ip", "-o", "link", "show"))
        if (links.exitCode != 0) return null
        val addresses = execute(listOf("ip", "-4", "-o", "addr", "show"))
        if (addresses.exitCode != 0) return null
        return RootHotspotInterfaceEvidence.parse(links.stdout, addresses.stdout)
    }

    /** Refuse inconsistent inventories, failed commands and unreadable output. */
    fun stableInventory(): RootHotspotInterfaceEvidence.Inventory? {
        return try {
            val first = inventory() ?: return null
            val second = inventory() ?: return null
            second.takeIf { first.sameTopology(it) }
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            null
        } catch (_: Exception) {
            null
        }
    }

    fun stopped(
        identity: RootHotspotInterfaceEvidence.Identity,
        platform: () -> PlatformObservation?,
    ): Boolean {
        return try {
            val before = platform() ?: return false
            if (before.session != identity.session || !before.requestRetired ||
                before.state !in setOf(RootHotspotInterfaceEvidence.PlatformState.ABSENT,
                    RootHotspotInterfaceEvidence.PlatformState.INACTIVE)) return false
            val inventory = stableInventory() ?: return false
            val after = platform() ?: return false
            if (before != after) return false
            RootHotspotInterfaceEvidence.stopped(identity, RootHotspotInterfaceEvidence.StopObservation(
                after.session, after.requestRetired, after.state, inventory,
            ))
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        } catch (_: Exception) {
            false
        }
    }
}
