package com.dpsmpx.dppass.connection

import kotlin.test.Test
import kotlin.test.assertEquals

class Zapret2BackendTest {
    @Test fun valuesRoundTrip() {
        Zapret2Backend.entries.forEach { assertEquals(it, Zapret2Backend.of(it.wire)) }
    }
    @Test fun unexpectedValuesNeverSelectRoot() {
        listOf(null, "", "root;whoami", "vpn").forEach {
            assertEquals(Zapret2Backend.OFF, Zapret2Backend.of(it))
        }
    }
    @Test fun providerRoundTripRemembersExplicitLocalExecutor() {
        Zapret2Backend.entries.filter { it != Zapret2Backend.OFF }.forEach {
            assertEquals(it, Zapret2Backend.preferredLocal(Zapret2Backend.OFF, it.wire))
            assertEquals(it, Zapret2Backend.preferredLocal(it, null))
        }
    }

    @Test fun unknownHistoryDefaultsToUnprivilegedAuto() {
        listOf(null, "", "off", "future", "root;whoami").forEach {
            assertEquals(Zapret2Backend.VPN_SERVICE, Zapret2Backend.preferredLocal(Zapret2Backend.OFF, it))
        }
    }

    @Test fun everyNewRootChoiceRequiresExplicitConfirmation() {
        for (current in Zapret2Backend.entries) for (requested in Zapret2Backend.entries) {
            assertEquals(requested.rooted && current != requested,
                Zapret2Backend.requiresRootConfirmation(current, requested))
        }
    }
}
