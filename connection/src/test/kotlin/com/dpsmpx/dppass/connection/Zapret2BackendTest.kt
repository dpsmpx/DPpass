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
}
