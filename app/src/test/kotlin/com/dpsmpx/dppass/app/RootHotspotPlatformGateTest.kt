package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotPlatformGateTest {
    private val request = RootHotspotLifecycle.Request(9, RootHotspotAdmission.Mode.VPN)
    private val session = RootHotspotAdmission.Session(9, 12, request.mode)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val active = RootHotspotPlatformGate.Observation(request,
        RootHotspotInterfaceEvidence.PlatformState.LOCAL_ONLY, setOf("wlan1"), "192.168.43.1", false)
    private val absent = RootHotspotPlatformGate.Observation(request,
        RootHotspotInterfaceEvidence.PlatformState.ABSENT, emptySet(), null, true)

    private class Resource
    private inner class Fixture {
        val resource = Resource()
        var observation: RootHotspotPlatformGate.Observation? = active
        var hasAp = true
        var onRead: () -> Unit = {}
        val gate = RootHotspotPlatformGate<Resource>(request, RootHotspotInventoryObserver { args ->
            val links = "1: lo: <LOOPBACK> mtu 65536\n" +
                if (hasAp) "12: wlan1: <UP> mtu 1500\n" else ""
            val addresses = "1: lo inet 127.0.0.1/8 scope host lo\n" +
                if (hasAp) "12: wlan1 inet 192.168.43.1/24 scope global wlan1\n" else ""
            RootCommandRunner.CompleteResult(0, if ("link" in args) links else addresses)
        }) { onRead(); observation }
        fun start() { gate.dispatched(); gate.started(resource) }
    }

    @Test fun callbackAloneDoesNotProveIdentity() {
        val f = Fixture()
        f.start()
        f.observation = null
        assertNull(f.gate.discover(f.resource))
        f.observation = active
        assertEquals(identity, f.gate.discover(f.resource))
        assertNull(f.gate.discover(Resource()))
    }

    @Test fun wrongRequestOrMultipleInterfacesRejectDiscovery() {
        val f = Fixture()
        f.start()
        f.observation = active.copy(request = request.copy(generation = 10))
        assertNull(f.gate.discover(f.resource))
        f.observation = active.copy(localOnlyInterfaces = setOf("wlan1", "wlan2"))
        assertNull(f.gate.discover(f.resource))
    }

    @Test fun callbackChangeDuringDiscoveryInvalidatesEvidence() {
        val f = Fixture()
        f.start()
        f.onRead = { f.gate.terminal() }
        assertNull(f.gate.discover(f.resource))
    }

    @Test fun terminalCallbackCannotProveShutdownWithResidualInterface() {
        val f = Fixture()
        f.start()
        f.gate.terminal()
        assertFalse(f.gate.stopped(identity))
        f.observation = absent
        assertFalse(f.gate.stopped(identity))
        f.hasAp = false
        assertTrue(f.gate.stopped(identity))
    }

    @Test fun exactReleaseAndIndependentRetirementAreBothRequiredWhileStarted() {
        val f = Fixture()
        f.start()
        f.hasAp = false
        f.observation = absent
        f.gate.released(Resource())
        assertFalse(f.gate.stopped(identity))
        f.gate.released(f.resource)
        f.observation = absent.copy(requestRetired = false)
        assertFalse(f.gate.stopped(identity))
        f.observation = absent
        assertTrue(f.gate.stopped(identity))
    }

    @Test fun unknownIdentityRequiresPositiveAbsenceAndLateEventsInvalidateProof() {
        val f = Fixture()
        f.gate.dispatched()
        f.gate.dispatchFailed()
        f.hasAp = false
        f.observation = absent.copy(state = RootHotspotInterfaceEvidence.PlatformState.INACTIVE)
        assertFalse(f.gate.stopped(null))
        f.observation = absent
        f.onRead = { f.gate.started(Resource()) }
        assertFalse(f.gate.stopped(null))
        f.onRead = {}
        assertTrue(f.gate.stopped(null))
    }
}
