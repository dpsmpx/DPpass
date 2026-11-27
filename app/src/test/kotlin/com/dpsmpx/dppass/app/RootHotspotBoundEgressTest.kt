package com.dpsmpx.dppass.app

import java.util.UUID
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNotEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotBoundEgressTest {
    private val request = RootHotspotLifecycle.Request(9, RootHotspotAdmission.Mode.VPN)
    private val session = RootHotspotAdmission.Session(9, 12, request.mode)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val owner = RootHotspotOwner(RootOwnerIdentity(123, "456"), UUID.randomUUID())
    private val token = UUID.fromString("12345678-1234-4234-9234-123456789abc")
    private val slot = RootHotspotNetworkFixture.slot
    private fun pending(token: UUID = this.token) =
        RootHotspotClaim.pending(request.generation, request.mode, owner, slot, token = token)
    private val complete = RootHotspotAdmission.Evidence(true, session, session, session, session, session, session)

    private inner class Fixture {
        val calls = mutableListOf<String>()
        var factoryFails = false
        lateinit var plan: RootHotspotNetworkPlan
        val egress = RootHotspotBoundEgress<Unit>(request) { bound, selected ->
            calls += "assemble"
            check(!factoryFails)
            plan = selected
            assertEquals(bound.networkPlan(identity).generation, plan.generation)
            object : RootHotspotServiceRuntime.Egress<Unit> {
                override fun prepare(resource: Unit, identity: RootHotspotInterfaceEvidence.Identity,
                                     owned: (String) -> Boolean) = complete.also { calls += "prepare" }
                override fun attach(identity: RootHotspotInterfaceEvidence.Identity, owned: (String) -> Boolean) =
                    true.also { calls += "attach" }
                override fun stop(identity: RootHotspotInterfaceEvidence.Identity?, owned: (String) -> Boolean) =
                    true.also { calls += "stop" }
                override fun cleanup(identity: RootHotspotInterfaceEvidence.Identity) = "exact cleanup"
                override fun verifyReady(session: RootHotspotAdmission.Session) = true
            }
        }
    }

    @Test fun markerAndSlotAreDeterministicFromPersistedClaim() {
        val first = pending().bind(session).claim.networkPlan(identity)
        val recovered = RootHotspotClaim.fromRecord(RootHotspotOwnerRecord(session, token, owner, slot)).networkPlan(identity)
        assertEquals(slot, first.slot)
        assertEquals("dpgateway", first.tun)
        assertEquals(first.generation, recovered.generation)
        assertTrue(first.generation.matches(Regex("[0-9a-f]{16}")))
        assertNotEquals(first.generation, pending(UUID.randomUUID()).bind(session).claim.networkPlan(identity).generation)
    }

    @Test fun pendingOrForeignClaimCannotProducePlan() {
        assertThrows(IllegalArgumentException::class.java) { pending().networkPlan(identity) }
        val bound = pending().bind(session).claim
        assertThrows(IllegalArgumentException::class.java) {
            bound.networkPlan(identity.copy(session = session.copy(generation = 10)))
        }
        assertThrows(IllegalArgumentException::class.java) { bound.networkPlan(identity.copy(name = "dpgateway")) }
    }

    @Test fun injectionDoesNotAssembleUntilPreparation() {
        val f = Fixture()
        f.egress.bindPendingClaim(pending())
        assertTrue(f.calls.isEmpty())
        assertEquals(complete, f.egress.prepare(Unit, identity) { true })
        assertEquals(listOf("assemble", "prepare"), f.calls)
        assertEquals(slot, f.plan.slot)
        assertTrue(f.egress.attach(identity) { true })
        assertTrue(f.egress.verifyReady(session))
        assertFalse(f.egress.verifyReady(session.copy(generation = 10)))
        assertTrue(f.egress.stop(identity) { true })
        assertEquals("exact cleanup", f.egress.cleanup(identity))
    }

    @Test fun mismatchedOrDuplicateClaimRejectedBeforeAssembly() {
        val f = Fixture()
        val wrong = RootHotspotClaim.pending(10, request.mode, owner, slot)
        assertThrows(IllegalArgumentException::class.java) { f.egress.bindPendingClaim(wrong) }
        f.egress.bindPendingClaim(pending())
        assertThrows(IllegalStateException::class.java) { f.egress.bindPendingClaim(pending()) }
        assertTrue(f.calls.isEmpty())
    }

    @Test fun prepareWithoutClaimNeverAssemblesAndCannotBeRetried() {
        val f = Fixture()
        assertThrows(IllegalStateException::class.java) { f.egress.prepare(Unit, identity) { true } }
        assertThrows(IllegalStateException::class.java) { f.egress.prepare(Unit, identity) { true } }
        assertTrue(f.calls.isEmpty())
        assertTrue(f.egress.stop(identity) { error("no mutation") })
    }

    @Test fun wrongSessionNeverAssembles() {
        val f = Fixture()
        f.egress.bindPendingClaim(pending())
        assertThrows(IllegalArgumentException::class.java) {
            f.egress.prepare(Unit, identity.copy(session = session.copy(generation = 10))) { true }
        }
        assertTrue(f.calls.isEmpty())
    }

    @Test fun sideEffectFreeAssemblyFailureAllowsRollbackWithoutMutations() {
        val f = Fixture()
        f.factoryFails = true
        f.egress.bindPendingClaim(pending())
        assertThrows(IllegalStateException::class.java) { f.egress.prepare(Unit, identity) { true } }
        assertTrue(f.egress.stop(identity) { error("must not mutate") })
        assertEquals(":", f.egress.cleanup(identity))
        assertFalse(f.egress.verifyReady(session))
    }

    @Test fun delegateCannotBeUsedForAnotherIdentity() {
        val f = Fixture()
        f.egress.bindPendingClaim(pending())
        f.egress.prepare(Unit, identity) { true }
        val wrong = identity.copy(name = "wlan2")
        assertThrows(IllegalArgumentException::class.java) { f.egress.attach(wrong) { true } }
        assertThrows(IllegalArgumentException::class.java) { f.egress.stop(wrong) { true } }
        assertThrows(IllegalArgumentException::class.java) { f.egress.cleanup(wrong) }
        assertEquals(listOf("assemble", "prepare"), f.calls)
    }
}
