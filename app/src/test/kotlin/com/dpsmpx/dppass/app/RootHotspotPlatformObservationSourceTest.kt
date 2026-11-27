package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotPlatformObservationSourceTest {
    private val request = RootHotspotLifecycle.Request(9, RootHotspotAdmission.Mode.VPN)
    private val session = RootHotspotAdmission.Session(9, 12, request.mode)
    private val identity = RootHotspotInterfaceEvidence.Identity(session, "wlan1", "192.168.43.1")
    private val active = RootHotspotPlatformObservationSource.OwnerEvidence.Active(request, identity)
    private val retired = RootHotspotPlatformObservationSource.OwnerEvidence.Retired(request, identity)

    private inner class Fixture {
        var row = "wlan1 - LocalHotspotState - lastError = 0\n"
        var link = "12: wlan1: <UP> mtu 1500\n"
        var address = "12: wlan1 inet 192.168.43.1/24 scope global wlan1\n"
        var upstream = "null"
        var proof: RootHotspotPlatformObservationSource.OwnerEvidence? = active
        var afterRead: () -> Unit = {}
        val source = RootHotspotPlatformObservationSource(request,
            RootHotspotTetherObserver {
                RootCommandRunner.CompleteResult(0, "Tethering:\n Tether state:\n" + row +
                    "Upstream wanted: false\nCurrent upstream interface(s): $upstream\n" +
                    "Hardware offload:\n fixture\nLog:\n<log removed for brevity>\n")
            },
            RootHotspotInventoryObserver { args ->
                val output = if ("link" in args) "1: lo: <LOOPBACK> mtu 65536\n" + link
                    else "1: lo inet 127.0.0.1/8 scope host lo\n" + address
                RootCommandRunner.CompleteResult(0, output)
            }) { proof.also { afterRead() } }
        fun gone() { row = ""; link = ""; address = ""; proof = retired }
    }

    @Test fun globalIdleBaselineMustBePositive() {
        val f = Fixture()
        assertFalse(f.source.idleBeforeDispatch())
        f.gone()
        assertTrue(f.source.idleBeforeDispatch())
        f.upstream = "[rmnet0]"
        assertFalse(f.source.idleBeforeDispatch())
    }

    @Test fun activeEvidenceMustAgreeWithGlobalAndKernelState() {
        val f = Fixture()
        assertEquals(RootHotspotInterfaceEvidence.PlatformState.LOCAL_ONLY, f.source.observe()?.state)
        f.proof = null
        assertNull(f.source.observe())
        f.proof = active.copy(request = request.copy(generation = 10))
        assertNull(f.source.observe())
        f.proof = active.copy(identity = identity.copy(session = session.copy(downstreamIndex = 13)))
        assertNull(f.source.observe())
        f.proof = active
        f.row += "rndis0 - TetheredState - lastError = 0\n"
        assertNull(f.source.observe())
    }

    @Test fun ownerChangeDuringSamplingInvalidatesEvidence() {
        val f = Fixture()
        f.afterRead = { f.proof = retired }
        assertNull(f.source.observe())
    }

    @Test fun retiredProofDoesNotOverrideResidualAddressOrInterface() {
        val f = Fixture()
        f.proof = retired
        assertNull(f.source.observe())
        f.row = ""
        assertNull(f.source.observe())
        f.link = ""
        f.address = ""
        assertEquals(RootHotspotInterfaceEvidence.PlatformState.ABSENT, f.source.observe()?.state)
    }

    @Test fun inactiveRequiresExactInterfaceIndexAndNoAddress() {
        val f = Fixture()
        f.proof = retired
        f.row = "wlan1 - AvailableState - lastError = 0\n"
        f.address = ""
        assertEquals(RootHotspotInterfaceEvidence.PlatformState.INACTIVE, f.source.observe()?.state)
        f.link = "13: wlan1: <UP> mtu 1500\n"
        assertNull(f.source.observe())
    }

    @Test fun unknownIdentityRequiresIndependentNoCreationProof() {
        val f = Fixture()
        f.gone()
        f.proof = null
        assertNull(f.source.observe())
        f.proof = retired.copy(identity = null)
        assertTrue(f.source.observe()?.requestRetired == true)
        f.upstream = "[rmnet0]"
        assertNull(f.source.observe())
    }
}
