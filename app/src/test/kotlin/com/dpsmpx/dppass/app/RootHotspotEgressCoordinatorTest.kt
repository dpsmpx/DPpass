package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotEgressCoordinatorTest {
    private class Resource
    private val session = RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val plan = RootHotspotNetworkPlan(identity, "dpgateway", RootHotspotNetworkFixture.slot, "0123456789abcdef")
    private val complete = RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)

    private inner class Fixture : RootHotspotEgressCoordinator.Driver<Resource> {
        val calls = mutableListOf<String>()
        var platform = true
        var guard = true
        var engine = true
        var stopped = true
        var attached = true
        var evidence = complete
        var scriptOk = true
        val coordinator = RootHotspotEgressCoordinator({ plan }, this)
        val resource = Resource()
        val owned: (String) -> Boolean = {
            calls += when (it) {
                plan.guard() -> "guard-script"
                plan.attach() -> "attach-script"
                plan.detach() -> "detach-script"
                else -> error("unexpected script")
            }
            scriptOk
        }
        override fun platformSafe(resource: Resource, identity: RootHotspotInterfaceEvidence.Identity) = platform.also { calls += "platform" }
        override fun verifyGuard(plan: RootHotspotNetworkPlan) = guard.also { calls += "verify-guard" }
        override fun startEngine(resource: Resource, plan: RootHotspotNetworkPlan) = engine.also { calls += "engine" }
        override fun evidence(plan: RootHotspotNetworkPlan) = evidence.also { calls += "evidence" }
        override fun verifyAttached(plan: RootHotspotNetworkPlan) = attached.also { calls += "verify-attach" }
        override fun stopEngine(plan: RootHotspotNetworkPlan) = stopped.also { calls += "stop-engine" }
        override fun verifyEngineStopped(plan: RootHotspotNetworkPlan) = stopped.also { calls += "verify-stop" }
        fun prepare() = coordinator.prepare(resource, identity, owned)
        fun attach() = coordinator.attach(identity, owned)
        fun stop() = coordinator.stop(identity, owned)
    }

    @Test fun completeOrderedLifecycle() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        assertTrue(f.attach())
        assertTrue(f.stop())
        assertEquals(plan.retire(), f.coordinator.cleanup(identity))
        assertEquals(listOf("platform", "guard-script", "verify-guard", "engine", "evidence",
            "platform", "verify-guard", "evidence", "attach-script", "verify-attach",
            "detach-script", "stop-engine", "verify-stop"), f.calls)
    }

    @Test fun unknownPlatformDoesNotInstallGuardOrStartEngine() {
        val f = Fixture()
        f.platform = false
        assertFalse(f.prepare().rootBaseline)
        assertEquals(listOf("platform"), f.calls)
        assertTrue(f.stop())
    }

    @Test fun guardFailureNeverStartsEngine() {
        val f = Fixture()
        f.guard = false
        assertFalse(f.prepare().rootBaseline)
        assertFalse("engine" in f.calls)
        assertTrue(f.stop())
    }

    @Test fun partialEngineStartRequiresStop() {
        val f = Fixture()
        f.engine = false
        assertFalse(f.prepare().rootBaseline)
        f.stopped = false
        assertFalse(f.stop())
        assertThrows(IllegalStateException::class.java) { f.coordinator.cleanup(identity) }
        f.stopped = true
        assertTrue(f.stop())
    }

    @Test fun staleEvidenceBeforeAttachRefusesWithoutMutation() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        f.evidence = complete.copy(noOffloadBypass = null)
        assertFalse(f.attach())
        assertFalse("attach-script" in f.calls)
        assertTrue(f.stop())
    }

    @Test fun failedAttachmentStillStopsEngineAndRetriesExactDetach() {
        val f = Fixture()
        f.prepare()
        f.attached = false
        assertFalse(f.attach())
        f.scriptOk = false
        assertFalse(f.stop())
        assertTrue("stop-engine" in f.calls)
        f.scriptOk = true
        assertTrue(f.stop())
        assertEquals(2, f.calls.count { it == "detach-script" })
        assertEquals(1, f.calls.count { it == "stop-engine" })
    }
}
