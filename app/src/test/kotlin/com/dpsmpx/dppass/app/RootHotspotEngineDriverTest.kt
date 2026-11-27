package com.dpsmpx.dppass.app

import com.dpsmpx.dppass.core.ProfileId
import com.dpsmpx.dppass.engine.CompiledConfig
import com.dpsmpx.dppass.engine.TunInput
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotEngineDriverTest {
    private val identity = RootHotspotInterfaceEvidence.Identity(
        RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN), "wlan1", "192.168.43.1")
    private val plan = RootHotspotNetworkPlan(identity, "dpgateway", RootHotspotNetworkFixture.slot, "0123456789abcdef")
    private val config = CompiledConfig("xray", "test", ProfileId("guest"), "{}", "fixture")
    private val complete = RootHotspotAdmission.Evidence(true, identity.session, identity.session,
        identity.session, identity.session, identity.session, identity.session)

    private inner class Fixture {
        val calls = mutableListOf<String>()
        var compiled: CompiledConfig? = config
        var reserve = true
        var stop = true
        var proof = complete
        val owner = RootHotspotEngineOwner {
            calls += "reserve"
            if (!reserve) null else object : RootHotspotEngineOwner.Lease {
                override fun start(config: CompiledConfig, input: TunInput) = true.also { calls += "start" }
                override fun stop() = stop.also { calls += "stop" }
                override fun releaseAfterTunClosed(verifiedClosed: Boolean) = verifiedClosed
            }
        }
        val driver = RootHotspotEngineDriver<Unit>(owner, {
            assertEquals(identity.session, it)
            compiled
        }, { _, selected ->
            assertTrue(selected === plan)
            calls += "acquire"
            object : RootHotspotEngineOwner.Tun {
                override val input = TunInput(42, 1500) { true }
                override fun close() { calls += "close" }
                override fun verifyClosed() = true
            }
        }, object : RootHotspotEngineDriver.Proof<Unit> {
            override fun platformSafe(resource: Unit, identity: RootHotspotInterfaceEvidence.Identity) = true
            override fun guard(plan: RootHotspotNetworkPlan) = true
            override fun evidence(plan: RootHotspotNetworkPlan) = proof
            override fun attached(plan: RootHotspotNetworkPlan) = true
        })
    }

    @Test fun missingConfigNeverAcquiresEngineOrTun() {
        val f = Fixture()
        f.compiled = null
        assertFalse(f.driver.startEngine(Unit, plan))
        assertFalse(f.driver.evidence(plan).rootBaseline)
        assertTrue(f.driver.stopEngine(plan))
        assertTrue(f.driver.verifyEngineStopped(plan))
        assertTrue(f.calls.isEmpty())
    }

    @Test fun busyEngineNeverAcquiresTun() {
        val f = Fixture()
        f.reserve = false
        assertFalse(f.driver.startEngine(Unit, plan))
        assertEquals(listOf("reserve"), f.calls)
        assertTrue(f.driver.stopEngine(plan))
        assertTrue(f.driver.verifyEngineStopped(plan))
    }

    @Test fun nativeStartDoesNotReplaceIndependentProof() {
        val f = Fixture()
        assertTrue(f.driver.startEngine(Unit, plan))
        f.proof = complete.copy(noOffloadBypass = null)
        assertEquals(RootHotspotAdmission.Refusal.OFFLOAD,
            RootHotspotAdmission.refusal(identity.session, f.driver.evidence(plan)))
        assertTrue(f.driver.stopEngine(plan))
        assertTrue(f.driver.verifyEngineStopped(plan))
        assertFalse(f.driver.verifyAttached(plan))
    }

    @Test fun stopFailureRetainsResourcesAndBlocksProof() {
        val f = Fixture()
        assertTrue(f.driver.startEngine(Unit, plan))
        f.stop = false
        assertFalse(f.driver.stopEngine(plan))
        assertFalse(f.driver.verifyEngineStopped(plan))
        assertFalse(f.driver.evidence(plan).rootBaseline)
        assertFalse("close" in f.calls)
        f.stop = true
        assertTrue(f.driver.stopEngine(plan))
        assertTrue(f.driver.verifyEngineStopped(plan))
    }
}
