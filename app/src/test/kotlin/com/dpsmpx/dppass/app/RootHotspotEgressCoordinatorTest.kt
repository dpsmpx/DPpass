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
        var healthy = true
        var guard = true
        var engine = true
        var stopped = true
        var attached = true
        var evidence = complete
        var scriptOk = true
        var vacant = true
        var firewallAttached = false
        var firewallAvailable = true
        val firewall = RootHotspotFirewallEvidence.Observer { args ->
            val chain = RootHotspotFirewallEvidence.Chain.entries.single { it.command == args }
            val rules = plan.firewallExpected(firewallAttached).getValue(chain)
            RootCommandRunner.CompleteResult(if (firewallAvailable) 0 else 1,
                (listOf("-P " + chain.chain + " ACCEPT") + rules).joinToString("\n", postfix = "\n"))
        }
        var routingAvailable = true
        val routing = RootHotspotRoutingEvidence.Observer { args ->
            val lookup = "400: from all iif wlan1 lookup 12000\n"
            val terminal = "401: from all iif wlan1 unreachable\n"
            val result = when {
                args[2] == "route" -> if (args[1] == "-6") "" else
                    (if (firewallAttached) "default dev dpgateway scope link metric 100\n" else "") +
                        "unreachable default metric 32767\n"
                args.size == 4 -> "0: from all lookup local\n" +
                    (if (args[1] == "-4") lookup else "") + terminal
                else -> if (args[1] == "-4") lookup else ""
            }
            RootCommandRunner.CompleteResult(if (routingAvailable) 0 else 1, result)
        }
        val coordinator = RootHotspotEgressCoordinator({ plan }, this, firewall, routing)
        val resource = Resource()
        val owned: (String) -> Boolean = {
            calls += when (it) {
                plan.vacancy() -> "vacancy"
                plan.guard() -> "guard-script"
                plan.attach() -> "attach-script"
                plan.detach() -> "detach-script"
                else -> error("unexpected script")
            }
            if (scriptOk && it == plan.attach()) firewallAttached = true
            if (scriptOk && it == plan.detach()) firewallAttached = false
            scriptOk && (it != plan.vacancy() || vacant)
        }
        override fun platformSafe(resource: Resource, identity: RootHotspotInterfaceEvidence.Identity) = platform.also { calls += "platform" }
        override fun verifyGuard(plan: RootHotspotNetworkPlan) = guard.also { calls += "verify-guard" }
        override fun startEngine(resource: Resource, plan: RootHotspotNetworkPlan) = engine.also { calls += "engine" }
        override fun evidence(plan: RootHotspotNetworkPlan) = evidence.also { calls += "evidence" }
        override fun engineHealthy(plan: RootHotspotNetworkPlan) = healthy
        override fun verifyAttached(plan: RootHotspotNetworkPlan) = attached.also { calls += "verify-attach" }
        override fun stopEngine(plan: RootHotspotNetworkPlan) = stopped.also { calls += "stop-engine" }
        override fun verifyEngineStopped(plan: RootHotspotNetworkPlan) = stopped.also { calls += "verify-stop" }
        fun prepare() = coordinator.prepare(resource, identity, owned)
        fun attach() = coordinator.attach(identity, owned)
        fun stop() = coordinator.stop(identity, owned)
    }

    @Test fun runningSessionChecksEveryIndependentEvidenceSource() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        assertTrue(f.attach())
        assertTrue(f.coordinator.verifyReady(session))
        assertFalse(f.coordinator.verifyReady(session.copy(generation = 10)))
        f.healthy = false
        assertFalse(f.coordinator.verifyReady(session))
        f.healthy = true
        f.routingAvailable = false
        assertFalse(f.coordinator.verifyReady(session))
        f.routingAvailable = true
        f.firewallAvailable = false
        assertFalse(f.coordinator.verifyReady(session))
        f.firewallAvailable = true
        f.evidence = complete.copy(noOffloadBypass = null)
        assertFalse(f.coordinator.verifyReady(session))
        f.evidence = complete
        f.platform = false
        assertFalse(f.coordinator.verifyReady(session))
        f.platform = true
        assertTrue(f.stop())
        assertFalse(f.coordinator.verifyReady(session))
    }

    @Test fun completeOrderedLifecycle() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        assertTrue(f.attach())
        assertTrue(f.stop())
        assertEquals(plan.retire(), f.coordinator.cleanup(identity))
        assertEquals(listOf("platform", "vacancy", "guard-script", "verify-guard", "engine", "evidence",
            "platform", "verify-guard", "evidence", "attach-script", "verify-attach",
            "detach-script", "stop-engine", "verify-stop"), f.calls)
    }

    @Test fun unknownPlatformDoesNotInstallGuardOrStartEngine() {
        val f = Fixture()
        f.platform = false
        assertFalse(f.prepare().rootBaseline)
        assertEquals(listOf("platform"), f.calls)
        assertTrue(f.stop())
        assertEquals(":", f.coordinator.cleanup(identity))
    }

    @Test fun occupiedSlotDoesNotAuthorizeAnyCleanupMutation() {
        val f = Fixture()
        f.vacant = false
        assertFalse(f.prepare().rootBaseline)
        assertEquals(listOf("platform", "vacancy"), f.calls)
        assertTrue(f.stop())
        assertEquals(":", f.coordinator.cleanup(identity))
    }

    @Test fun guardFailureNeverStartsEngine() {
        val f = Fixture()
        f.guard = false
        assertFalse(f.prepare().rootBaseline)
        assertFalse("engine" in f.calls)
        assertTrue(f.stop())
        assertEquals(plan.retire(), f.coordinator.cleanup(identity))
    }

    @Test fun independentFirewallFailureBlocksEngineDespiteSuccessfulGuardScript() {
        val f = Fixture()
        f.firewallAvailable = false
        assertFalse(f.prepare().rootBaseline)
        assertFalse("engine" in f.calls)
        assertTrue(f.stop())
    }

    @Test fun lostFirewallProofBeforeAttachBlocksMutation() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        f.firewallAvailable = false
        assertFalse(f.attach())
        assertFalse("attach-script" in f.calls)
        assertTrue(f.stop())
    }

    @Test fun detachedFirewallProofRequiredBeforeRetiringGuards() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        assertTrue(f.attach())
        f.firewallAvailable = false
        assertFalse(f.stop())
        assertThrows(IllegalStateException::class.java) { f.coordinator.cleanup(identity) }
        f.firewallAvailable = true
        assertTrue(f.stop())
        assertEquals(plan.retire(), f.coordinator.cleanup(identity))
    }

    @Test fun failedRoutingEvidenceBlocksEngineAndAttachment() {
        val first = Fixture()
        first.routingAvailable = false
        assertFalse(first.prepare().rootBaseline)
        assertFalse("engine" in first.calls)
        val second = Fixture()
        assertEquals(complete, second.prepare())
        second.routingAvailable = false
        assertFalse(second.attach())
        assertFalse("attach-script" in second.calls)
    }

    @Test fun lostRoutingProofAfterDetachRetainsCleanup() {
        val f = Fixture()
        assertEquals(complete, f.prepare())
        assertTrue(f.attach())
        f.routingAvailable = false
        assertFalse(f.stop())
        assertThrows(IllegalStateException::class.java) { f.coordinator.cleanup(identity) }
        f.routingAvailable = true
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
