package com.dpsmpx.dppass.app

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertNull
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class RootHotspotOffloadEvidenceTest {
    private val identity = RootHotspotInterfaceEvidence.Identity(
        RootHotspotAdmission.Session(9, 12, RootHotspotAdmission.Mode.VPN), "wlan1", "192.168.43.1")
    private fun dump(hardware: String = "Offload disabled",
                     bpf: String? = "mIsBpfEnabled: false\nPolling not started\nStats provider not registered",
                     iface: String = "wlan1 - LocalHotspotState - lastError = 0",
                     upstream: String = "null"): String =
        "Tethering:\n Tether state:\n $iface\n Upstream wanted: false\n" +
            " Current upstream interface(s): $upstream\n Hardware offload:\n $hardware\n" +
            (bpf?.let { " BPF offload:\n $it\n" } ?: "") +
            " Log:\n <log removed for brevity>\n"

    @Test fun explicitDisabledStatesAreNecessaryOnly() {
        val snapshot = checkNotNull(RootHotspotOffloadEvidence.parse(dump()))
        assertEquals(RootHotspotOffloadEvidence.Hardware.DISABLED, snapshot.hardware)
        assertEquals(RootHotspotOffloadEvidence.Bpf.DISABLED, snapshot.bpf)
        assertTrue(snapshot.allowsObservation(identity))
        assertFalse(snapshot.allowsObservation(identity.copy(name = "wlan2")))
    }

    @Test fun stoppedHalIsNotExplicitlyDisabled() {
        val snapshot = checkNotNull(RootHotspotOffloadEvidence.parse(
            dump(hardware = "Offload HALs not started\nCurrent upstream: null")))
        assertEquals(RootHotspotOffloadEvidence.Hardware.STOPPED, snapshot.hardware)
        assertFalse(snapshot.explicitlyDisabled)
    }

    @Test fun enabledHardwareOrBpfVetoes() {
        assertFalse(checkNotNull(RootHotspotOffloadEvidence.parse(
            dump(hardware = "Offload HALs started"))).allowsObservation(identity))
        assertFalse(checkNotNull(RootHotspotOffloadEvidence.parse(
            dump(bpf = "mIsBpfEnabled: true\nPolling not started"))).allowsObservation(identity))
    }

    @Test fun missingAndUnknownVendorFieldsNeverConfirmDisabled() {
        for (raw in listOf(dump(bpf = null), dump(hardware = "Disabled"),
            dump(bpf = "BPF disabled"), dump(bpf = "mIsBpfEnabled: false"),
            dump(bpf = "mIsBpfEnabled: false\nPolling started"))) {
            assertFalse(checkNotNull(RootHotspotOffloadEvidence.parse(raw)).explicitlyDisabled)
        }
    }

    @Test fun conflictingFlagsAndRepeatedSectionsFailClosed() {
        val conflict = dump(bpf = "mIsBpfEnabled: false\nPolling not started\nmIsBpfEnabled: true")
        assertFalse(checkNotNull(RootHotspotOffloadEvidence.parse(conflict)).explicitlyDisabled)
        assertNull(RootHotspotOffloadEvidence.parse(dump(bpf = "BPF offload:\nmIsBpfEnabled: false\nPolling not started")))
    }

    @Test fun incompleteAndErrorOutputNeverConfirms() {
        assertNull(RootHotspotOffloadEvidence.parse(dump().substringBefore(" Log:")))
        assertNull(RootHotspotOffloadEvidence.parse(dump(bpf =
            "mIsBpfEnabled: false\nPolling not started\nError dumping BPF stats map: unavailable")))
        assertNull(RootHotspotOffloadEvidence.parse(dump().replace("\n", "\r\n")))
    }

    @Test fun globalTetherOrUpstreamPreventsObservation() {
        for (raw in listOf(dump(iface = "wlan1 - TetheredState - lastError = 0"),
            dump(upstream = "rmnet0"),
            dump(iface = "wlan1 - LocalHotspotState - lastError = 0\nwlan2 - LocalHotspotState - lastError = 0"))) {
            assertFalse(checkNotNull(RootHotspotOffloadEvidence.parse(raw)).allowsObservation(identity))
        }
    }

    @Test fun observerRequiresTwoMatchingSuccessfulSamples() {
        var count = 0
        val observer = RootHotspotOffloadEvidence.Observer {
            assertEquals(listOf("dumpsys", "tethering", "--short"), it)
            RootCommandRunner.CompleteResult(0, if (++count == 1) dump() else dump(bpf = "mIsBpfEnabled: true"))
        }
        assertFalse(observer.allows(identity))
        assertEquals(2, count)
        assertTrue(RootHotspotOffloadEvidence.Observer {
            RootCommandRunner.CompleteResult(0, dump())
        }.allows(identity))
        assertFalse(RootHotspotOffloadEvidence.Observer {
            RootCommandRunner.CompleteResult(1, dump())
        }.allows(identity))
    }

    @Test fun interruptedObservationPreservesInterrupt() {
        val observer = RootHotspotOffloadEvidence.Observer { throw InterruptedException() }
        try {
            assertFalse(observer.allows(identity))
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }
}
